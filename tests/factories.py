"""Synthetic captures with known packet-number evidence."""

from __future__ import annotations

from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6DestUnreach, IPv6
from scapy.layers.l2 import Dot1Q, Ether
from scapy.packet import Raw
from scapy.utils import PcapNgWriter, wrpcap

SECRET_PAYLOAD = b"Authorization: Bearer framecite-super-secret prompt-injection-ignore-rules"


def ethernet() -> Ether:
    return Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")


def troubleshooting_packets() -> list[object]:
    client = "10.0.0.10"
    server = "10.0.0.20"
    dns_server = "10.0.0.53"
    packets = [
        ethernet() / IP(src=client, dst=server) / TCP(sport=40000, dport=443, flags="S", seq=100),
        ethernet()
        / IP(src=server, dst=client)
        / TCP(sport=443, dport=40000, flags="SA", seq=200, ack=101),
        ethernet()
        / IP(src=client, dst=server)
        / TCP(sport=40000, dport=443, flags="A", seq=101, ack=201),
        ethernet()
        / IP(src=client, dst=server)
        / TCP(sport=40000, dport=443, flags="PA", seq=101, ack=201)
        / Raw(SECRET_PAYLOAD),
        ethernet()
        / IP(src=client, dst=server)
        / TCP(sport=40000, dport=443, flags="PA", seq=101, ack=201)
        / Raw(SECRET_PAYLOAD),
        ethernet()
        / IP(src=server, dst=client)
        / TCP(sport=443, dport=40000, flags="A", seq=201, ack=170, window=0),
        ethernet()
        / IP(src=server, dst=client)
        / TCP(sport=443, dport=40000, flags="R", seq=201, ack=170),
        ethernet()
        / IP(src=client, dst=dns_server)
        / UDP(sport=53000, dport=53)
        / DNS(id=10, rd=1, qd=DNSQR(qname="good.example")),
        ethernet()
        / IP(src=dns_server, dst=client)
        / UDP(sport=53, dport=53000)
        / DNS(
            id=10,
            qr=1,
            aa=1,
            qd=DNSQR(qname="good.example"),
            an=DNSRR(rrname="good.example", rdata="192.0.2.10"),
        ),
        ethernet()
        / IP(src=client, dst=dns_server)
        / UDP(sport=53001, dport=53)
        / DNS(id=20, rd=1, qd=DNSQR(qname="missing.example")),
        ethernet()
        / IP(src=dns_server, dst=client)
        / UDP(sport=53, dport=53001)
        / DNS(id=20, qr=1, rcode=3, qd=DNSQR(qname="missing.example")),
        ethernet()
        / IP(src=client, dst=dns_server)
        / UDP(sport=53002, dport=53)
        / DNS(id=30, rd=1, qd=DNSQR(qname="unanswered.example")),
        ethernet()
        / IP(src=client, dst=dns_server)
        / UDP(sport=53002, dport=53)
        / DNS(id=30, rd=1, qd=DNSQR(qname="unanswered.example")),
        ethernet() / IP(src=server, dst=client) / ICMP(type=3, code=1),
        ethernet()
        / IP(src=client, dst="10.0.0.30")
        / TCP(sport=41000, dport=22, flags="S", seq=500),
        ethernet()
        / Dot1Q(vlan=100)
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / UDP(sport=12345, dport=54321),
    ]
    base_time = 1_700_000_000.0
    for index, packet in enumerate(packets):
        packet.time = base_time + index * 0.01  # type: ignore[attr-defined]
    return packets


def write_troubleshooting_pcap(path: Path) -> Path:
    wrpcap(str(path), troubleshooting_packets())
    return path


def write_troubleshooting_pcapng(path: Path) -> Path:
    writer = PcapNgWriter(str(path))
    try:
        for packet in troubleshooting_packets():
            writer.write(packet)
    finally:
        writer.close()
    return path


def write_dns_port_reuse_pcap(path: Path) -> Path:
    """Write same-ID DNS queries on distinct source ports with one response."""

    client = "10.0.0.10"
    dns_server = "10.0.0.53"
    packets = [
        ethernet()
        / IP(src=client, dst=dns_server)
        / UDP(sport=53000, dport=53)
        / DNS(id=42, rd=1, qd=DNSQR(qname="port-reuse.example")),
        ethernet()
        / IP(src=client, dst=dns_server)
        / UDP(sport=53001, dport=53)
        / DNS(id=42, rd=1, qd=DNSQR(qname="port-reuse.example")),
        ethernet()
        / IP(src=dns_server, dst=client)
        / UDP(sport=53, dport=53000)
        / DNS(id=42, qr=1, qd=DNSQR(qname="port-reuse.example")),
    ]
    base_time = 1_700_100_000.0
    for index, packet in enumerate(packets):
        packet.time = base_time + index * 0.01  # type: ignore[attr-defined]
    wrpcap(str(path), packets)
    return path


def write_dns_case_variant_pcap(path: Path) -> Path:
    """Write a DNS pair whose question name differs only by case."""

    client = "10.0.0.10"
    dns_server = "10.0.0.53"
    packets = [
        ethernet()
        / IP(src=client, dst=dns_server)
        / UDP(sport=53100, dport=53)
        / DNS(id=43, rd=1, qd=DNSQR(qname="MiXeD.Example")),
        ethernet()
        / IP(src=dns_server, dst=client)
        / UDP(sport=53, dport=53100)
        / DNS(id=43, qr=1, qd=DNSQR(qname="mixed.example")),
    ]
    base_time = 1_700_200_000.0
    for index, packet in enumerate(packets):
        packet.time = base_time + index * 0.01  # type: ignore[attr-defined]
    wrpcap(str(path), packets)
    return path


def write_dns_response_before_query_pcap(path: Path) -> Path:
    """Write a stale response before the only matching DNS query."""

    client = "10.0.0.10"
    dns_server = "10.0.0.53"
    packets = [
        ethernet()
        / IP(src=dns_server, dst=client)
        / UDP(sport=53, dport=53200)
        / DNS(id=44, qr=1, qd=DNSQR(qname="ordered.example")),
        ethernet()
        / IP(src=client, dst=dns_server)
        / UDP(sport=53200, dport=53)
        / DNS(id=44, qd=DNSQR(qname="ordered.example")),
    ]
    wrpcap(str(path), packets)
    return path


def write_mdns_pcap(path: Path) -> Path:
    """Write one multicast-DNS query and response with multicast endpoints."""

    multicast = "224.0.0.251"
    packets = [
        ethernet()
        / IP(src="10.0.0.10", dst=multicast)
        / UDP(sport=5353, dport=5353)
        / DNS(id=0, qd=DNSQR(qname="printer.local")),
        ethernet()
        / IP(src="10.0.0.20", dst=multicast)
        / UDP(sport=5353, dport=5353)
        / DNS(id=0, qr=1, qd=DNSQR(qname="printer.local")),
    ]
    wrpcap(str(path), packets)
    return path


def write_tcp_syn_repeat_pcap(path: Path) -> Path:
    """Write two same-four-tuple SYN packets with no observed SYN-ACK."""

    packets = [
        ethernet()
        / IP(src="10.0.0.10", dst="10.0.0.20")
        / TCP(sport=44000, dport=443, flags="S", seq=100),
        ethernet()
        / IP(src="10.0.0.10", dst="10.0.0.20")
        / TCP(sport=44000, dport=443, flags="S", seq=100),
    ]
    base_time = 1_700_300_000.0
    for index, packet in enumerate(packets):
        packet.time = base_time + index * 0.5  # type: ignore[attr-defined]
    wrpcap(str(path), packets)
    return path


def write_tcp_rst_zero_window_pcap(path: Path) -> Path:
    """Write a zero-window RST followed by a real zero-window advertisement."""

    packets = [
        ethernet()
        / IP(src="10.0.0.20", dst="10.0.0.10")
        / TCP(sport=443, dport=45000, flags="RA", window=0),
        ethernet()
        / IP(src="10.0.0.20", dst="10.0.0.10")
        / TCP(sport=443, dport=45000, flags="A", window=0),
    ]
    wrpcap(str(path), packets)
    return path


def write_tcp_syn_order_pcap(path: Path) -> Path:
    """Write a stale SYN-ACK plus two SYN epochs with only one valid response."""

    packets = [
        ethernet()
        / IP(src="10.0.0.20", dst="10.0.0.10")
        / TCP(sport=443, dport=46000, flags="SA", seq=900, ack=101),
        ethernet()
        / IP(src="10.0.0.10", dst="10.0.0.20")
        / TCP(sport=46000, dport=443, flags="S", seq=100),
        ethernet()
        / IP(src="10.0.0.10", dst="10.0.0.20")
        / TCP(sport=46000, dport=443, flags="S", seq=200),
        ethernet()
        / IP(src="10.0.0.20", dst="10.0.0.10")
        / TCP(sport=443, dport=46000, flags="SA", seq=901, ack=101),
    ]
    wrpcap(str(path), packets)
    return path


def write_icmp_quoted_dns_pcap(path: Path) -> Path:
    """Write an ICMP error quoting DNS plus one direct DNS transaction."""

    client = "10.0.0.10"
    dns_server = "10.0.0.53"
    quoted = (
        ethernet()
        / IP(src="192.0.2.1", dst=client)
        / ICMP(type=3, code=3)
        / IP(src=client, dst=dns_server)
        / UDP(sport=53000, dport=53)
        / DNS(id=90, qd=DNSQR(qname="quoted-secret.internal"))
    )
    query = (
        ethernet()
        / IP(src=client, dst=dns_server)
        / UDP(sport=53001, dport=53)
        / DNS(id=91, qd=DNSQR(qname="direct-secret.internal"))
    )
    response = (
        ethernet()
        / IP(src=dns_server, dst=client)
        / UDP(sport=53, dport=53001)
        / DNS(id=91, qr=1, qd=DNSQR(qname="direct-secret.internal"))
    )
    wrpcap(str(path), [quoted, query, response])
    return path


def write_icmpv6_error_pcap(path: Path) -> Path:
    packet = ethernet() / IPv6(src="2001:db8::2", dst="2001:db8::1") / ICMPv6DestUnreach(code=1)
    wrpcap(str(path), [packet])
    return path


def write_out_of_order_timestamps_pcap(path: Path) -> Path:
    packets = [
        ethernet() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8),
        ethernet() / IP(src="10.0.0.2", dst="10.0.0.1") / ICMP(type=0),
    ]
    packets[0].time = 1_700_400_000.2  # type: ignore[attr-defined]
    packets[1].time = 1_700_400_000.1  # type: ignore[attr-defined]
    wrpcap(str(path), packets)
    return path
