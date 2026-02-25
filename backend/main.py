from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
from typing import List, Dict, Any, Optional
from collections import OrderedDict
import uuid
import shutil
import logging
from pathlib import Path
import time

from packet_parser import PacketParser
from llm_router import LLMRouter, LLMProvider

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Packet Analysis Tool API")

CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:8501").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "./uploads"))
UPLOAD_DIR.mkdir(exist_ok=True)

MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "100"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024

MAX_SESSIONS = int(os.getenv("MAX_SESSIONS", "50"))


class PcapAnalysisResponse(BaseModel):
    session_id: str
    summary: Dict[str, Any]
    top_talkers: Dict[str, Any]
    protocol_distribution: Dict[str, int]
    packet_count: int


class ChatRequest(BaseModel):
    session_id: str
    query: str
    llm_provider: Optional[LLMProvider] = LLMProvider.ANTHROPIC


class ChatResponse(BaseModel):
    response: str


class PacketDetailsResponse(BaseModel):
    packets: List[Dict[str, Any]]
    total: int
    offset: int
    count: int


llm_router = LLMRouter()

sessions: OrderedDict = OrderedDict()

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}


def _evict_sessions():
    """Remove oldest sessions when over the limit."""
    while len(sessions) > MAX_SESSIONS:
        evicted_id, evicted = sessions.popitem(last=False)
        logger.info(f"Evicted session {evicted_id} (limit: {MAX_SESSIONS})")
        session_dir = Path(evicted.get("file_path", "")).parent
        if session_dir.exists() and session_dir != UPLOAD_DIR:
            shutil.rmtree(session_dir, ignore_errors=True)


@app.get("/health")
async def health_check():
    return {"status": "ok"}


@app.post("/api/upload", response_model=PcapAnalysisResponse)
async def upload_pcap(file: UploadFile = File(...)):
    try:
        safe_filename = Path(file.filename).name if file.filename else "upload.pcap"
        if not any(safe_filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
            raise HTTPException(status_code=400, detail="Only .pcap and .pcapng files are accepted")

        session_id = str(uuid.uuid4())

        session_dir = UPLOAD_DIR / session_id
        session_dir.mkdir(exist_ok=True)

        file_path = session_dir / safe_filename
        if not file_path.resolve().is_relative_to(session_dir.resolve()):
            raise HTTPException(status_code=400, detail="Invalid filename")

        size = 0
        with file_path.open("wb") as buffer:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    buffer.close()
                    shutil.rmtree(session_dir, ignore_errors=True)
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds maximum upload size of {MAX_UPLOAD_SIZE_MB} MB",
                    )
                buffer.write(chunk)

        parser = PacketParser(str(file_path))
        summary = parser.get_summary()

        sessions[session_id] = {
            "file_path": str(file_path),
            "parser": parser,
            "filename": file.filename,
            "created_at": time.time(),
        }
        _evict_sessions()

        return {
            "session_id": session_id,
            "summary": summary,
            "top_talkers": parser.get_top_talkers(),
            "protocol_distribution": parser.get_protocol_distribution(),
            "packet_count": parser.get_packet_count(),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing PCAP file: {str(e)}")
        raise HTTPException(status_code=500, detail="Error processing PCAP file")


@app.post("/api/chat", response_model=ChatResponse)
async def chat_with_pcap(request: ChatRequest):
    try:
        if request.session_id not in sessions:
            raise HTTPException(status_code=404, detail="Session not found")

        session = sessions[request.session_id]
        parser = session["parser"]

        context = parser.get_llm_context()

        response = await llm_router.query(
            query=request.query,
            context=context,
            provider=request.llm_provider,
        )

        return {"response": response}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing chat request: {str(e)}")
        raise HTTPException(status_code=500, detail="Error processing chat request")


@app.get("/api/packet-details/{session_id}", response_model=PacketDetailsResponse)
async def get_packet_details(
    session_id: str,
    packet_index: int = Query(default=0, ge=0),
    count: int = Query(default=10, ge=1, le=500),
):
    try:
        if session_id not in sessions:
            raise HTTPException(status_code=404, detail="Session not found")

        session = sessions[session_id]
        parser = session["parser"]

        packets = parser.get_packets(start=packet_index, count=count)
        total = parser.get_packet_count()
        return {
            "packets": packets,
            "total": total,
            "offset": packet_index,
            "count": len(packets),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting packet details: {str(e)}")
        raise HTTPException(status_code=500, detail="Error getting packet details")


@app.get("/api/sessions")
async def list_sessions():
    result = []
    for session_id, data in sessions.items():
        result.append({
            "session_id": session_id,
            "filename": data.get("filename", "Unknown"),
        })
    return {"sessions": result}


@app.delete("/api/sessions/{session_id}")
async def delete_session(session_id: str):
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    evicted = sessions.pop(session_id)
    session_dir = Path(evicted.get("file_path", "")).parent
    if session_dir.exists() and session_dir != UPLOAD_DIR:
        shutil.rmtree(session_dir, ignore_errors=True)
    return {"status": "deleted", "session_id": session_id}


@app.get("/api/llm-providers")
async def get_llm_providers():
    available = llm_router.get_available_providers()
    return {"providers": available}


@app.get("/")
async def root():
    return {"message": "Packet Analysis Tool API"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
