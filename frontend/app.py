import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import httpx
import json
import time
import os
from enum import Enum
import asyncio
import base64
from typing import Dict, List, Any, Optional

# LLM Provider options (must match the backend enum)
class LLMProvider(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    OLLAMA = "ollama"

# API connection settings
API_URL = os.getenv("API_URL", "http://backend:8000")

# Set page config
st.set_page_config(
    page_title="PacketPilot",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Helper functions
async def upload_pcap(file):
    """Upload a PCAP file to the backend."""
    files = {"file": (file.name, file, "application/octet-stream")}
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(f"{API_URL}/api/upload", files=files)
        if response.status_code != 200:
            st.error(f"Error uploading file: {response.text}")
            return None
        return response.json()

async def chat_query(session_id, query, llm_provider):
    """Send a chat query to the backend."""
    payload = {
        "session_id": session_id,
        "query": query,
        "llm_provider": llm_provider
    }
    
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(f"{API_URL}/api/chat", json=payload)
        if response.status_code != 200:
            st.error(f"Error sending query: {response.text}")
            return None
        return response.json()

async def get_packet_details(session_id, packet_index=0, count=100):
    """Get packet details from the backend."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.get(
            f"{API_URL}/api/packet-details/{session_id}?packet_index={packet_index}&count={count}"
        )
        if response.status_code != 200:
            st.error(f"Error getting packet details: {response.text}")
            return None
        return response.json()

# Initialize session state
if "session_id" not in st.session_state:
    st.session_state.session_id = None
if "analysis_data" not in st.session_state:
    st.session_state.analysis_data = None
if "packets" not in st.session_state:
    st.session_state.packets = []
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "current_provider" not in st.session_state:
    st.session_state.current_provider = LLMProvider.ANTHROPIC

# Sidebar
with st.sidebar:
    st.title("🔍 Packet Analyzer")
    
    # File uploader
    uploaded_file = st.file_uploader("Upload PCAP file", type=["pcap", "pcapng"])
    
    if uploaded_file is not None:
        # Upload button
        if st.button("Analyze File"):
            with st.spinner("Uploading and analyzing file..."):
                result = asyncio.run(upload_pcap(uploaded_file))
                if result:
                    st.session_state.session_id = result["session_id"]
                    st.session_state.analysis_data = result
                    # Load initial packet details
                    packet_details = asyncio.run(get_packet_details(result["session_id"]))
                    if packet_details:
                        st.session_state.packets = packet_details["packets"]
                    st.success(f"Successfully analyzed {uploaded_file.name}")
                    st.rerun()
    
    # LLM provider selection
    st.subheader("LLM Settings")
    llm_provider = st.selectbox(
        "Select LLM Provider",
        [provider.value for provider in LLMProvider],
        index=[provider.value for provider in LLMProvider].index(st.session_state.current_provider)
    )
    if llm_provider != st.session_state.current_provider:
        st.session_state.current_provider = llm_provider

# Main content area
if st.session_state.session_id is None:
    st.title("Network Packet Analyzer")
    st.info("📤 Upload a PCAP file using the sidebar to get started.")
    
    # Show example queries
    st.subheader("Example Queries You Can Ask")
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        - Identify potential port scanning activity
        - What is the most common protocol in this capture?
        - Explain the TCP handshake in this capture
        - Are there any failed connection attempts?
        - Find suspicious outbound connections
        """)
    with col2:
        st.markdown("""
        - Summarize the DNS traffic in this capture
        - Are there any HTTP errors?
        - What's the average packet size?
        - Find potential data exfiltration attempts
        - Identify devices on the local network
        """)
else:
    # Tabs for different views
    tab1, tab2, tab3 = st.tabs(["Dashboard", "Packet Explorer", "Chat Analysis"])
    
    # Dashboard tab
    with tab1:
        st.title("Network Traffic Dashboard")
        
        # Summary metrics
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
            file_size_mb = summary.get('file_size_bytes', 0) / (1024 * 1024)
            st.metric("File Size", f"{file_size_mb:.2f} MB")
        
        # Protocol distribution
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
                    color_discrete_sequence=px.colors.qualitative.Dark24
                )
                fig.update_layout(legend=dict(orientation="h", yanchor="bottom", y=-0.3))
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No protocol data available")
        
        # Top talkers
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
                        color_discrete_sequence=px.colors.qualitative.Dark24
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No top talkers data available")
            else:
                st.info("No top talkers data available")
        
        # Top connections
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
                    color_discrete_sequence=px.colors.qualitative.G10
                )
                fig.update_layout(xaxis_tickangle=-45)
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No connection data available")
        else:
            st.info("No connection data available")
    
    # Packet Explorer tab
    with tab2:
        st.title("Packet Explorer")
        
        # Pagination controls
        st.subheader("Packet List")
        col1, col2, col3 = st.columns([1, 2, 1])
        with col1:
            page_size = st.selectbox("Packets per page", [10, 25, 50, 100], index=0)
        with col2:
            page = st.number_input("Page", min_value=1, value=1, step=1)
        with col3:
            if st.button("Load Packets"):
                start_idx = (page - 1) * page_size
                with st.spinner("Loading packets..."):
                    packet_data = asyncio.run(get_packet_details(
                        st.session_state.session_id,
                        packet_index=start_idx,
                        count=page_size
                    ))
                    if packet_data:
                        st.session_state.packets = packet_data["packets"]
        
        # Display packets
        if st.session_state.packets:
            for i, packet in enumerate(st.session_state.packets):
                with st.expander(f"Packet #{packet['index']}: {', '.join([layer['type'] for layer in packet['layers']])}"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write("**Packet Info:**")
                        st.write(f"Length: {packet['length']} bytes")
                        st.write(f"Time: {packet['time']}")
                    
                    # Display layers
                    st.write("**Layers:**")
                    for layer in packet['layers']:
                        layer_type = layer['type']
                        st.write(f"**{layer_type}**")
                        
                        # Layer-specific details
                        if layer_type in ["Ethernet", "IPv4", "IPv6"]:
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
                            flags = [flag for flag, val in layer['flags'].items() if val]
                            st.write(f"Flags: {' '.join(flags)}")
                        
                        if layer_type == "UDP":
                            st.write(f"Source Port: {layer['sport']}")
                            st.write(f"Destination Port: {layer['dport']}")
                            st.write(f"Length: {layer['len']}")
                        
                        if layer_type == "ICMP":
                            st.write(f"Type: {layer['type_id']}")
                            st.write(f"Code: {layer['code']}")
                    
                    # Payload (if available)
                    if "payload" in packet:
                        st.write("**Payload:**")
                        st.text(packet["payload"])
        else:
            st.info("No packets loaded. Use the controls above to load packets.")
    
    # Chat Analysis tab
    with tab3:
        st.title("LLM-Powered Packet Analysis")
        
        # Input area
        st.subheader("Ask about your capture")
        
        # Display chat history
        chat_container = st.container()
        with chat_container:
            for entry in st.session_state.chat_history:
                if entry["role"] == "user":
                    st.markdown(f"**You:** {entry['content']}")
                else:
                    st.markdown(f"**Assistant ({entry['provider']}):** {entry['content']}")
        
        # Query input
        query = st.text_area("Your question:", placeholder="Example: Explain what protocols are used in this capture")
        col1, col2 = st.columns([1, 4])
        with col1:
            if st.button("Ask", type="primary"):
                if query:
                    # Add user message to history
                    st.session_state.chat_history.append({
                        "role": "user",
                        "content": query,
                        "provider": st.session_state.current_provider
                    })
                    
                    # Get response from LLM
                    with st.spinner("Getting answer..."):
                        response = asyncio.run(chat_query(
                            st.session_state.session_id,
                            query,
                            st.session_state.current_provider
                        ))
                        
                        if response:
                            # Add assistant response to history
                            st.session_state.chat_history.append({
                                "role": "assistant",
                                "content": response["response"],
                                "provider": st.session_state.current_provider
                            })
                    st.rerun()

# Run the app
if __name__ == "__main__":
    st.write("Running in development mode")
