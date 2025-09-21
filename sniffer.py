import click
from typing import Callable
from scapy.all import sniff
from scapy.packet import Packet


class TCPSniffer:

    def __init__(self, packet_handler: Callable[[Packet], None] = None):
        self.is_running: bool = False
        self.packet_handler: Callable[[Packet], None] = packet_handler

    def start_sniffing(self, local_ip: str) -> None:
        """Starts sniffing TCP packets from the network."""
        try:
            self.is_running = True
            click.secho("SecureFlow started.", fg="green")
            click.echo("Press Ctrl+C to stop.")

            sniff(
                filter=f"tcp and not src host {local_ip}",
                prn=self.packet_handler,
                stop_filter=lambda _: not self.is_running
            )
        except Exception as e:
            click.secho(f"Error starting sniffer: {str(e)}", fg="red")

    def stop_sniffing(self) -> None:
        """Stops the packet-sniffing process by updating the `is_running` flag."""
        self.is_running = False
        click.secho("SecureFlow stopped.", fg="red")
