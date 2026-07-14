from scapy.all import Ether, IP, TCP, UDP, wrpcap

from packet_parser import PacketParser


def test_parser_summarizes_synthetic_capture(tmp_path):
    capture = tmp_path / "synthetic.pcap"
    packets = [
        Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(sport=50000, dport=443),
        Ether() / IP(src="198.51.100.20", dst="192.0.2.10") / TCP(sport=443, dport=50000),
        Ether() / IP(src="192.0.2.10", dst="192.0.2.53") / UDP(sport=53000, dport=53),
    ]
    wrpcap(str(capture), packets)

    parser = PacketParser(str(capture))

    assert parser.get_packet_count() == 3
    assert parser.get_summary()["packet_count"] == 3
    assert parser.get_protocol_distribution() == {
        "IPv4": 3,
        "TCP": 2,
        "UDP": 1,
        "DNS": 1,
    }
    assert parser.get_top_talkers()["top_ips"][0]["ip"] == "192.0.2.10"
