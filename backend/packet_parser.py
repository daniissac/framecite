import scapy.all as scapy
from scapy.utils import rdpcap
import pyshark
import json
from typing import List, Dict, Any, Optional
from collections import Counter, defaultdict
import ipaddress
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class PacketParser:
    def __init__(self, file_path: str, max_packets: int = 50000):
        """Initialize the packet parser with a PCAP file.
        
        Args:
            file_path: Path to the PCAP file
            max_packets: Maximum number of packets to analyze to prevent memory issues
        """
        self.file_path = file_path
        self.max_packets = max_packets
        self._packets_scapy = None
        self._packets_pyshark = None
        self._packet_count = 0
        self._load_packets()
    
    def _load_packets(self):
        """Load packets from the PCAP file using both Scapy and PyShark."""
        try:
            # Load with Scapy for quick metadata analysis
            logger.info(f"Loading PCAP with Scapy: {self.file_path}")
            self._packets_scapy = rdpcap(self.file_path, count=self.max_packets)
            self._packet_count = len(self._packets_scapy)
            logger.info(f"Loaded {self._packet_count} packets with Scapy")
            
            # Load with PyShark for detailed protocol analysis
            # Only load when needed to save memory
        except Exception as e:
            logger.error(f"Error loading PCAP file: {str(e)}")
            raise RuntimeError(f"Failed to load PCAP file: {str(e)}")
    
    def _get_pyshark_capture(self):
        """Get PyShark capture, loading it if not already loaded."""
        if not self._packets_pyshark:
            logger.info(f"Loading PCAP with PyShark: {self.file_path}")
            self._packets_pyshark = pyshark.FileCapture(self.file_path)
        return self._packets_pyshark
    
    def get_packet_count(self) -> int:
        """Get the total number of packets in the PCAP file."""
        return self._packet_count
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the PCAP file."""
        if not self._packets_scapy:
            return {"error": "No packets loaded"}
        
        try:
            # Calculate timespan
            timestamps = [pkt.time for pkt in self._packets_scapy]
            timespan = max(timestamps) - min(timestamps) if timestamps else 0
            
            return {
                "packet_count": self._packet_count,
                "file_size_bytes": Path(self.file_path).stat().st_size,
                "duration_seconds": timespan,
                "packets_per_second": self._packet_count / timespan if timespan > 0 else 0
            }
        except Exception as e:
            logger.error(f"Error generating summary: {str(e)}")
            return {"error": f"Failed to generate summary: {str(e)}"}
    
    def get_protocol_distribution(self) -> Dict[str, int]:
        """Get the distribution of protocols in the PCAP file."""
        if not self._packets_scapy:
            return {}
        
        protocols = {}
        
        try:
            # Layer 3 protocols
            ip_counter = 0
            ipv6_counter = 0
            
            # Layer 4 protocols
            tcp_counter = 0
            udp_counter = 0
            icmp_counter = 0
            
            # Layer 7 protocols - simplified
            http_counter = 0
            dns_counter = 0
            
            for pkt in self._packets_scapy:
                # Layer 3
                if pkt.haslayer(scapy.IP):
                    ip_counter += 1
                if pkt.haslayer(scapy.IPv6):
                    ipv6_counter += 1
                
                # Layer 4
                if pkt.haslayer(scapy.TCP):
                    tcp_counter += 1
                    
                    # Simplified HTTP detection (port-based)
                    if pkt.haslayer(scapy.TCP) and (pkt[scapy.TCP].dport == 80 or pkt[scapy.TCP].sport == 80):
                        http_counter += 1
                
                if pkt.haslayer(scapy.UDP):
                    udp_counter += 1
                    
                    # Simplified DNS detection (port-based)
                    if pkt.haslayer(scapy.UDP) and (pkt[scapy.UDP].dport == 53 or pkt[scapy.UDP].sport == 53):
                        dns_counter += 1
                
                if pkt.haslayer(scapy.ICMP):
                    icmp_counter += 1
            
            protocols = {
                "IPv4": ip_counter,
                "IPv6": ipv6_counter,
                "TCP": tcp_counter,
                "UDP": udp_counter,
                "ICMP": icmp_counter,
                "HTTP": http_counter,
                "DNS": dns_counter
            }
            
            return {k: v for k, v in protocols.items() if v > 0}
            
        except Exception as e:
            logger.error(f"Error getting protocol distribution: {str(e)}")
            return {"error": str(e)}
    
    def get_top_talkers(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """Get the top talkers (IP addresses) in the PCAP file."""
        if not self._packets_scapy:
            return []
        
        try:
            ip_counter = Counter()
            connections = Counter()
            
            for pkt in self._packets_scapy:
                if pkt.haslayer(scapy.IP):
                    src_ip = pkt[scapy.IP].src
                    dst_ip = pkt[scapy.IP].dst
                    
                    ip_counter[src_ip] += 1
                    ip_counter[dst_ip] += 1
                    
                    # Track connections (src-dst pairs)
                    conn = f"{src_ip} → {dst_ip}"
                    connections[conn] += 1
            
            # Get top IPs
            top_ips = [{"ip": ip, "packet_count": count} for ip, count in ip_counter.most_common(top_n)]
            
            # Get top connections
            top_connections = [{"connection": conn, "packet_count": count} 
                              for conn, count in connections.most_common(top_n)]
            
            return {
                "top_ips": top_ips,
                "top_connections": top_connections
            }
        except Exception as e:
            logger.error(f"Error getting top talkers: {str(e)}")
            return []
    
    def get_packets(self, start: int = 0, count: int = 10) -> List[Dict[str, Any]]:
        """Get a range of packets with detailed information."""
        if not self._packets_scapy:
            return []
        
        try:
            result = []
            end = min(start + count, len(self._packets_scapy))
            
            for i in range(start, end):
                pkt = self._packets_scapy[i]
                packet_data = {
                    "index": i,
                    "time": pkt.time,
                    "length": len(pkt),
                    "layers": []
                }
                
                # Process layers
                if pkt.haslayer(scapy.Ether):
                    eth = pkt[scapy.Ether]
                    packet_data["layers"].append({
                        "type": "Ethernet",
                        "src": eth.src,
                        "dst": eth.dst
                    })
                
                if pkt.haslayer(scapy.IP):
                    ip = pkt[scapy.IP]
                    packet_data["layers"].append({
                        "type": "IPv4",
                        "src": ip.src,
                        "dst": ip.dst,
                        "proto": ip.proto,
                        "ttl": ip.ttl
                    })
                
                if pkt.haslayer(scapy.IPv6):
                    ipv6 = pkt[scapy.IPv6]
                    packet_data["layers"].append({
                        "type": "IPv6",
                        "src": ipv6.src,
                        "dst": ipv6.dst,
                        "next_header": ipv6.nh
                    })
                
                if pkt.haslayer(scapy.TCP):
                    tcp = pkt[scapy.TCP]
                    packet_data["layers"].append({
                        "type": "TCP",
                        "sport": tcp.sport,
                        "dport": tcp.dport,
                        "flags": {
                            "S": 1 if tcp.flags.S else 0,
                            "A": 1 if tcp.flags.A else 0,
                            "F": 1 if tcp.flags.F else 0,
                            "R": 1 if tcp.flags.R else 0,
                            "P": 1 if tcp.flags.P else 0
                        },
                        "seq": tcp.seq,
                        "ack": tcp.ack
                    })
                
                if pkt.haslayer(scapy.UDP):
                    udp = pkt[scapy.UDP]
                    packet_data["layers"].append({
                        "type": "UDP",
                        "sport": udp.sport,
                        "dport": udp.dport,
                        "len": udp.len
                    })
                
                if pkt.haslayer(scapy.ICMP):
                    icmp = pkt[scapy.ICMP]
                    packet_data["layers"].append({
                        "type": "ICMP",
                        "type_id": icmp.type,
                        "code": icmp.code
                    })
                
                # Check for application layer data (simplified)
                if pkt.haslayer(scapy.Raw):
                    data = pkt[scapy.Raw].load
                    try:
                        data_str = data.decode('utf-8', errors='replace')
                        # Truncate if too long
                        if len(data_str) > 200:
                            data_str = data_str[:200] + "..."
                        packet_data["payload"] = data_str
                    except:
                        # If can't decode properly, just note binary data
                        packet_data["payload"] = f"Binary data ({len(data)} bytes)"
                
                result.append(packet_data)
            
            return result
        except Exception as e:
            logger.error(f"Error getting packets: {str(e)}")
            return []
    
    def get_llm_context(self) -> str:
        """Get a context string for LLM queries."""
        try:
            summary = self.get_summary()
            proto_dist = self.get_protocol_distribution()
            top_talkers = self.get_top_talkers(5)
            
            # Create a context string for the LLM
            context = f"""
PCAP File Summary:
- Total packets: {summary.get('packet_count', 0)}
- Duration: {summary.get('duration_seconds', 0):.2f} seconds
- Average packets/sec: {summary.get('packets_per_second', 0):.2f}

Protocol Distribution:
{json.dumps(proto_dist, indent=2)}

Top Talkers (IP addresses):
{json.dumps(top_talkers.get('top_ips', []), indent=2)}

Top Connections:
{json.dumps(top_talkers.get('top_connections', []), indent=2)}

Sample packets:
{json.dumps(self.get_packets(0, 5), indent=2)}
"""
            return context
        except Exception as e:
            logger.error(f"Error creating LLM context: {str(e)}")
            return f"Error creating context: {str(e)}"
