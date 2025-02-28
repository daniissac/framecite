from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import tempfile
import os
import json
from typing import List, Dict, Any, Optional
import asyncio
import uuid
import shutil
import logging
from pathlib import Path

from packet_parser import PacketParser
from llm_router import LLMRouter, LLMProvider

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="Packet Analysis Tool API")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
UPLOAD_DIR = Path("./uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# Models
class PcapAnalysisResponse(BaseModel):
    session_id: str
    summary: Dict[str, Any]
    top_talkers: List[Dict[str, Any]]
    protocol_distribution: Dict[str, int]
    packet_count: int

class ChatRequest(BaseModel):
    session_id: str
    query: str
    llm_provider: Optional[LLMProvider] = LLMProvider.ANTHROPIC

class ChatResponse(BaseModel):
    response: str

# Create services
llm_router = LLMRouter()

# Session storage - in a production app, use a proper database
sessions = {}

@app.post("/api/upload", response_model=PcapAnalysisResponse)
async def upload_pcap(file: UploadFile = File(...)):
    try:
        # Generate session ID
        session_id = str(uuid.uuid4())
        
        # Create session directory
        session_dir = UPLOAD_DIR / session_id
        session_dir.mkdir(exist_ok=True)
        
        # Save uploaded file
        file_path = session_dir / file.filename
        with file_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # Parse PCAP file
        parser = PacketParser(str(file_path))
        summary = parser.get_summary()
        
        # Store session data
        sessions[session_id] = {
            "file_path": str(file_path),
            "parser": parser,
            "filename": file.filename
        }
        
        return {
            "session_id": session_id,
            "summary": summary,
            "top_talkers": parser.get_top_talkers(),
            "protocol_distribution": parser.get_protocol_distribution(),
            "packet_count": parser.get_packet_count()
        }
    except Exception as e:
        logger.error(f"Error processing PCAP file: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error processing PCAP file: {str(e)}")

@app.post("/api/chat", response_model=ChatResponse)
async def chat_with_pcap(request: ChatRequest):
    try:
        if request.session_id not in sessions:
            raise HTTPException(status_code=404, detail="Session not found")
        
        session = sessions[request.session_id]
        parser = session["parser"]
        
        # Format packet data for LLM context
        context = parser.get_llm_context()
        
        # Send query to LLM
        response = await llm_router.query(
            query=request.query,
            context=context,
            provider=request.llm_provider
        )
        
        return {"response": response}
    except Exception as e:
        logger.error(f"Error processing chat request: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error processing chat request: {str(e)}")

@app.get("/api/packet-details/{session_id}")
async def get_packet_details(session_id: str, packet_index: int = 0, count: int = 10):
    try:
        if session_id not in sessions:
            raise HTTPException(status_code=404, detail="Session not found")
        
        session = sessions[session_id]
        parser = session["parser"]
        
        packets = parser.get_packets(start=packet_index, count=count)
        return {"packets": packets}
    except Exception as e:
        logger.error(f"Error getting packet details: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting packet details: {str(e)}")

@app.get("/api/sessions")
async def list_sessions():
    result = []
    for session_id, data in sessions.items():
        result.append({
            "session_id": session_id,
            "filename": data.get("filename", "Unknown")
        })
    return {"sessions": result}

@app.get("/")
async def root():
    return {"message": "Packet Analysis Tool API"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
