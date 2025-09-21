import time
import click
import alert
from scapy.layers.inet import IP, TCP
from typing import Callable


class TrafficAnalyzer:
    """Analyzes network traffic to detect SYN Flood attacks based on SYN packet rates."""

    def __init__(self, threshold: int = 100, window: int = 10, on_attack: Callable[[str], None] = None):
        self.threshold: int = threshold  # Max SYN packets per window
        self.window: int = window  # Time window in seconds
        self.on_attack: Callable[[str], None] = on_attack  # Callback when attack is detected
        self.syn_times: dict = {}  # Tracks timestamps per IP

    def handle_packet(self, packet) -> None:
        """Processes incoming packets to detect suspicious SYN Flood activity."""
        try:
            if packet.haslayer(TCP) and packet.haslayer(IP):
                tcp_flags = packet[TCP].flags
                src_ip = packet[IP].src

                click.echo(f"\rChecking TCP packet from {src_ip}:{packet[TCP].sport}", nl=False)

                # Check for SYN without ACK
                if 'S' in tcp_flags and 'A' not in tcp_flags:
                    current_time = time.time()

                    # Initialize the list if the IP doesn't exist
                    if src_ip not in self.syn_times:
                        self.syn_times[src_ip] = []

                    # Remove old timestamps outside the window and validate they are not None
                    valid_timestamps = []
                    for timestamp in self.syn_times[src_ip]:
                        if current_time - timestamp <= self.window:
                            valid_timestamps.append(timestamp)

                    self.syn_times[src_ip] = valid_timestamps

                    # Add new timestamp
                    self.syn_times[src_ip].append(current_time)

                    click.secho(f"\nCurrent traffic from {src_ip}: {len(self.syn_times[src_ip])} SYN packets in {self.window} seconds.", fg="yellow")

                    # Check threshold
                    if len(self.syn_times[src_ip]) >= self.threshold:
                        click.secho("\nSYN FLOOD ATTACK DETECTED!", fg="red", bold=True)
                        click.secho(f"Suspicious IP: {src_ip}", fg="red")

                        alert.send_attack_alert(src_ip, len(self.syn_times[src_ip]), self.threshold, self.window)

                        if self.on_attack:
                            self.on_attack(src_ip)

                        self.syn_times[src_ip].clear()  # Reset after alert
        except Exception as e:
            click.secho(f"Error processing packet: {e}", fg="red")
