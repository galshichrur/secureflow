import time
import click
import alert
from scapy.layers.inet import IP, TCP
from typing import Callable, Union, Dict, List, Optional


class TrafficAnalyzer:
    """Analyzes network traffic to detect SYN Flood attacks based on SYN packet rates."""

    def __init__(self, threshold: int = 100, window: int = 10, alert_timeout: int = 300, on_attack: Callable[[str], None] = None):
        self.threshold: int = threshold  # Max SYN packets per window
        self.window: int = window  # Time window in seconds
        self.alert_timeout: int = alert_timeout  # Alert timeout when there is an attack
        self.on_attack: Callable[[str], None] = on_attack  # Callback when attack is detected
        self.syn_times: Dict[str, List[float]] = {}  # Tracks timestamps per IP
        self.latest_attack: Optional[float] = None

    def handle_packet(self, packet) -> None:
        """Processes incoming packets to detect suspicious SYN Flood activity."""
        try:
            if packet.haslayer(TCP) and packet.haslayer(IP):

                current_time = time.time()

                # If latest attack time is less than alert timeout
                if (self.latest_attack is not None) and (current_time - self.latest_attack < self.alert_timeout):
                    click.secho(f"\rAlert timeout...", fg="yellow", nl=False)
                    return

                tcp_flags = packet[TCP].flags
                src_ip = packet[IP].src

                click.echo(f"\rChecking TCP packet from {src_ip}:{packet[TCP].sport}", nl=False)

                # If not SYN packet
                if not ('S' in tcp_flags and 'A' not in tcp_flags):
                    return

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

                # Check threshold
                if len(self.syn_times[src_ip]) >= self.threshold:

                    self.latest_attack = current_time

                    click.secho("\nSYN FLOOD ATTACK DETECTED!", fg="red", bold=True)
                    click.secho(f"Suspicious IP: {src_ip}", fg="red")

                    alert.send_attack_alert(src_ip, len(self.syn_times[src_ip]), self.threshold, self.window)

                    # Call on attack function
                    if self.on_attack:
                        self.on_attack(src_ip)

                    self.syn_times[src_ip].clear()  # Reset the counter for that IP

        except Exception as e:
            click.secho(f"Error processing packet: {e}", fg="red")
