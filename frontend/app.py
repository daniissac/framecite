import streamlit as st
import pandas as pd
import plotly.express as px
import httpx
import os
from enum import Enum
import asyncio
import math

API_URL = os.getenv("API_URL", "http://backend:8000")


class LLMProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    OLLAMA = "ollama"


st.set_page_config(
    page_title="PacketPilot",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------------------------
# API helpers with error handling
# ---------------------------------------------------------------------------

def _api_error(exc: Exception) -> None:
    """Display a user-friendly error for common httpx failures."""
    if isinstance(exc, httpx.ConnectError):
        st.error("Could not connect to the backend. Make sure the server is running.")
    elif isinstance(exc, httpx.TimeoutException):
        st.error("Request timed out. The server may be busy -- try again.")
    elif isinstance(exc, httpx.HTTPStatusError):
        st.error(f"Server error ({exc.response.status_code}): {exc.response.text}")
    else:
        st.error(f"Unexpected error: {exc}")


async def upload_pcap(file):
    """Upload a PCAP file to the backend."""
    files = {"file": (file.name, file, "application/octet-stream")}
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(f"{API_URL}/api/upload", files=files)
        response.raise_for_status()
        return response.json()


async def chat_query(session_id: str, query: str, llm_provider):
    """Send a chat query to the backend."""
    provider_value = llm_provider.value if isinstance(llm_provider, LLMProvider) else llm_provider
    payload = {
        "session_id": session_id,
        "query": query,
        "llm_provider": provider_value,
    }
    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(f"{API_URL}/api/chat", json=payload)
        response.raise_for_status()
        return response.json()


async def get_packet_details(session_id: str, packet_index: int = 0, count: int = 100):
    """Get packet details from the backend."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{API_URL}/api/packet-details/{session_id}",
            params={"packet_index": packet_index, "count": count},
        )
        response.raise_for_status()
        return response.json()


async def fetch_providers():
    """Fetch available LLM providers from the backend."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(f"{API_URL}/api/llm-providers")
        response.raise_for_status()
        return response.json().get("providers", [])


# ---------------------------------------------------------------------------
# Session state initialisation
# ---------------------------------------------------------------------------

if "session_id" not in st.session_state:
    st.session_state.session_id = None
if "analysis_data" not in st.session_state:
    st.session_state.analysis_data = None
if "packets" not in st.session_state:
    st.session_state.packets = []
if "packet_meta" not in st.session_state:
    st.session_state.packet_meta = {"total": 0, "offset": 0, "count": 0}
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "current_provider" not in st.session_state:
    st.session_state.current_provider = LLMProvider.ANTHROPIC
if "available_providers" not in st.session_state:
    st.session_state.available_providers = [p.value for p in LLMProvider]
if "uploaded_filename" not in st.session_state:
    st.session_state.uploaded_filename = None
if "pkt_page" not in st.session_state:
    st.session_state.pkt_page = 1
if "pkt_page_size" not in st.session_state:
    st.session_state.pkt_page_size = 25


def _reset_session():
    """Clear all session-specific state for a fresh upload."""
    st.session_state.session_id = None
    st.session_state.analysis_data = None
    st.session_state.packets = []
    st.session_state.packet_meta = {"total": 0, "offset": 0, "count": 0}
    st.session_state.chat_history = []
    st.session_state.uploaded_filename = None
    st.session_state.pkt_page = 1


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.title("🔍 PacketPilot")

    uploaded_file = st.file_uploader("Upload PCAP file", type=["pcap", "pcapng"])

    if uploaded_file is not None:
        if st.button("Analyze File", type="primary"):
            _reset_session()
            with st.spinner("Uploading and analyzing file..."):
                try:
                    result = asyncio.run(upload_pcap(uploaded_file))
                    st.session_state.session_id = result["session_id"]
                    st.session_state.analysis_data = result
                    st.session_state.uploaded_filename = uploaded_file.name
                    try:
                        packet_details = asyncio.run(
                            get_packet_details(result["session_id"], 0, st.session_state.pkt_page_size)
                        )
                        st.session_state.packets = packet_details.get("packets", [])
                        st.session_state.packet_meta = {
                            "total": packet_details.get("total", 0),
                            "offset": packet_details.get("offset", 0),
                            "count": packet_details.get("count", 0),
                        }
                    except Exception:
                        pass
                    try:
                        providers = asyncio.run(fetch_providers())
                        st.session_state.available_providers = providers
                    except Exception:
                        pass
                    st.success(f"Analyzed {uploaded_file.name}")
                    st.rerun()
                except Exception as exc:
                    _api_error(exc)

    if st.session_state.uploaded_filename:
        st.divider()
        st.caption("Active capture")
        st.write(f"**{st.session_state.uploaded_filename}**")
        if st.session_state.analysis_data:
            pkt_count = st.session_state.analysis_data.get("packet_count", 0)
            st.write(f"{pkt_count:,} packets")

    st.divider()
    st.subheader("LLM Settings")

    provider_options = [p.value for p in LLMProvider]
    available = st.session_state.available_providers

    current_idx = 0
    if st.session_state.current_provider.value in provider_options:
        current_idx = provider_options.index(st.session_state.current_provider.value)

    llm_provider = st.selectbox(
        "Select LLM Provider",
        provider_options,
        index=current_idx,
        format_func=lambda p: f"{p}" if p in available else f"{p} (no API key)",
    )
    if llm_provider != st.session_state.current_provider.value:
        st.session_state.current_provider = LLMProvider(llm_provider)

    if llm_provider not in available:
        st.warning("This provider has no API key configured. The backend will fall back to an available provider.")


# ---------------------------------------------------------------------------
# Main content
# ---------------------------------------------------------------------------

if st.session_state.session_id is None:
    st.title("Network Packet Analyzer")
    st.info("Upload a PCAP file using the sidebar to get started.")

    st.subheader("Example Queries You Can Ask")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown(
            """
        - Identify potential port scanning activity
        - What is the most common protocol in this capture?
        - Explain the TCP handshake in this capture
        - Are there any failed connection attempts?
        - Find suspicious outbound connections
        """
        )
    with col2:
        st.markdown(
            """
        - Summarize the DNS traffic in this capture
        - Are there any HTTP errors?
        - What's the average packet size?
        - Find potential data exfiltration attempts
        - Identify devices on the local network
        """
        )
else:
    tab1, tab2, tab3 = st.tabs(["Dashboard", "Packet Explorer", "Chat Analysis"])

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------
    with tab1:
        st.title("Network Traffic Dashboard")

        st.subheader("Capture Summary")
        summary = st.session_state.analysis_data["summary"]
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Packets", f"{summary['packet_count']:,}")
        with col2:
            st.metric("Duration", f"{summary.get('duration_seconds', 0):.2f} sec")
        with col3:
            st.metric("Packets/Sec", f"{summary.get('packets_per_second', 0):.2f}")
        with col4:
            file_size_mb = summary.get("file_size_bytes", 0) / (1024 * 1024)
            st.metric("File Size", f"{file_size_mb:.2f} MB")

        st.subheader("Protocol Distribution")
        col1, col2 = st.columns(2)

        with col1:
            protocol_data = st.session_state.analysis_data["protocol_distribution"]
            if protocol_data:
                protocols = list(protocol_data.keys())
                counts = list(protocol_data.values())
                fig = px.pie(
                    values=counts,
                    names=protocols,
                    title="Protocol Distribution",
                    color_discrete_sequence=px.colors.qualitative.Dark24,
                )
                fig.update_layout(legend=dict(orientation="h", yanchor="bottom", y=-0.3))
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No protocol data available")

        with col2:
            if "top_talkers" in st.session_state.analysis_data:
                top_ips = st.session_state.analysis_data["top_talkers"].get("top_ips", [])
                if top_ips:
                    df = pd.DataFrame(top_ips)
                    fig = px.bar(
                        df,
                        x="ip",
                        y="packet_count",
                        title="Top IP Addresses",
                        labels={"ip": "IP Address", "packet_count": "Packet Count"},
                        color_discrete_sequence=px.colors.qualitative.Dark24,
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No top talkers data available")
            else:
                st.info("No top talkers data available")

        st.subheader("Top Connections")
        if "top_talkers" in st.session_state.analysis_data:
            top_connections = st.session_state.analysis_data["top_talkers"].get("top_connections", [])
            if top_connections:
                df = pd.DataFrame(top_connections)
                fig = px.bar(
                    df,
                    x="connection",
                    y="packet_count",
                    title="Top Connections",
                    labels={"connection": "Connection", "packet_count": "Packet Count"},
                    color_discrete_sequence=px.colors.qualitative.G10,
                )
                fig.update_layout(xaxis_tickangle=-45)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No connection data available")
        else:
            st.info("No connection data available")

    # ------------------------------------------------------------------
    # Packet Explorer
    # ------------------------------------------------------------------
    with tab2:
        st.title("Packet Explorer")

        total_packets = st.session_state.packet_meta.get("total", 0) or st.session_state.analysis_data.get("packet_count", 0)

        col1, col2 = st.columns([1, 3])
        with col1:
            page_size = st.selectbox(
                "Packets per page",
                [10, 25, 50, 100],
                index=[10, 25, 50, 100].index(st.session_state.pkt_page_size),
                key="pkt_size_select",
            )
        with col2:
            total_pages = max(1, math.ceil(total_packets / page_size)) if total_packets else 1
            page = st.number_input(
                f"Page (of {total_pages})",
                min_value=1,
                max_value=total_pages,
                value=min(st.session_state.pkt_page, total_pages),
                step=1,
                key="pkt_page_input",
            )

        need_reload = (
            page != st.session_state.pkt_page
            or page_size != st.session_state.pkt_page_size
            or not st.session_state.packets
        )

        if need_reload:
            st.session_state.pkt_page = page
            st.session_state.pkt_page_size = page_size
            start_idx = (page - 1) * page_size
            try:
                with st.spinner("Loading packets..."):
                    packet_data = asyncio.run(
                        get_packet_details(st.session_state.session_id, packet_index=start_idx, count=page_size)
                    )
                    st.session_state.packets = packet_data.get("packets", [])
                    st.session_state.packet_meta = {
                        "total": packet_data.get("total", total_packets),
                        "offset": packet_data.get("offset", start_idx),
                        "count": packet_data.get("count", len(st.session_state.packets)),
                    }
                    total_packets = st.session_state.packet_meta["total"]
            except Exception as exc:
                _api_error(exc)

        if total_packets:
            offset = st.session_state.packet_meta.get("offset", 0)
            shown = len(st.session_state.packets)
            st.caption(f"Showing packets {offset + 1}\u2013{offset + shown} of {total_packets:,}")

        if st.session_state.packets:
            for packet in st.session_state.packets:
                layer_names = ", ".join(layer["type"] for layer in packet["layers"])
                with st.expander(f"Packet #{packet['index']}: {layer_names}"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**Length:** {packet['length']} bytes")
                        st.write(f"**Time:** {packet['time']}")

                    st.write("**Layers:**")
                    for layer in packet["layers"]:
                        layer_type = layer["type"]
                        st.write(f"**{layer_type}**")

                        if layer_type in ("Ethernet", "IPv4", "IPv6"):
                            st.write(f"Source: {layer['src']}")
                            st.write(f"Destination: {layer['dst']}")

                        if layer_type == "IPv4":
                            st.write(f"TTL: {layer['ttl']}")
                            st.write(f"Protocol: {layer['proto']}")

                        if layer_type == "TCP":
                            st.write(f"Source Port: {layer['sport']}")
                            st.write(f"Destination Port: {layer['dport']}")
                            st.write(f"Sequence: {layer['seq']}")
                            st.write(f"Acknowledgment: {layer['ack']}")
                            flags = [flag for flag, val in layer["flags"].items() if val]
                            st.write(f"Flags: {' '.join(flags)}")

                        if layer_type == "UDP":
                            st.write(f"Source Port: {layer['sport']}")
                            st.write(f"Destination Port: {layer['dport']}")
                            st.write(f"Length: {layer['len']}")

                        if layer_type == "ICMP":
                            st.write(f"Type: {layer['type_id']}")
                            st.write(f"Code: {layer['code']}")

                    if "payload" in packet:
                        st.write("**Payload:**")
                        st.text(packet["payload"])
        else:
            st.info("No packets to display.")

    # ------------------------------------------------------------------
    # Chat Analysis
    # ------------------------------------------------------------------
    with tab3:
        st.title("LLM-Powered Packet Analysis")

        col_header, col_clear = st.columns([4, 1])
        with col_header:
            st.subheader("Ask about your capture")
        with col_clear:
            if st.button("Clear conversation"):
                st.session_state.chat_history = []
                st.rerun()

        for entry in st.session_state.chat_history:
            role = "user" if entry["role"] == "user" else "assistant"
            with st.chat_message(role):
                if role == "assistant":
                    st.caption(f"Provider: {entry.get('provider', 'unknown')}")
                st.markdown(entry["content"])

        if prompt := st.chat_input("Ask a question about your capture..."):
            st.session_state.chat_history.append({
                "role": "user",
                "content": prompt,
                "provider": st.session_state.current_provider.value,
            })
            with st.chat_message("user"):
                st.markdown(prompt)

            with st.chat_message("assistant"):
                with st.spinner("Thinking..."):
                    try:
                        response = asyncio.run(
                            chat_query(
                                st.session_state.session_id,
                                prompt,
                                st.session_state.current_provider,
                            )
                        )
                        answer = response.get("response", "No response received.")
                    except Exception as exc:
                        _api_error(exc)
                        answer = "Failed to get a response. See error above."

                st.caption(f"Provider: {st.session_state.current_provider.value}")
                st.markdown(answer)
                st.session_state.chat_history.append({
                    "role": "assistant",
                    "content": answer,
                    "provider": st.session_state.current_provider.value,
                })
