import rich_click as click
from sniffer import TCPSniffer
from analyzer import TrafficAnalyzer
from blocker import IPBlocker


blocker = IPBlocker()

@click.group()
def cli():
    """SecureFlow CLI - Protect your network from SYN Flood attacks."""
    pass

@click.command()
@click.argument("ip", help="Local IP address")
@click.option("--threshold", default=100, type=int, help="Set the threshold for SYN packets per window.")
@click.option("--window", default=10, type=int, help="Set the time window in seconds.")
@click.option("--alert-timeout", default=10, type=int, help="Set the alert timeout in seconds when there is an attack.")
def start(ip: str, threshold: int = 100, window: int = 10, alert_timeout: int = 300):
    """Start monitoring network traffic."""
    analyzer = TrafficAnalyzer(threshold, window, alert_timeout, on_attack=blocker.block_ip)
    sniffer = TCPSniffer(packet_handler=analyzer.handle_packet)

    sniffer.start_sniffing(ip)

@click.command()
@click.argument('ip')
def block(ip):
    """Manually block a specific IP address."""
    blocker.block_ip(ip)

@click.command()
@click.argument('ip')
def unblock(ip):
    """Unblock a previously blocked IP."""
    blocker.unblock_ip(ip)

@click.command()
@click.argument('ip')
def is_blocked(ip):
    """Check if an IP address is blocked."""
    if blocker.is_ip_blocked(ip):
        click.secho(f"IP {ip} is blocked.", fg="red")
    else:
        click.secho(f"IP {ip} is not blocked.", fg="green")

cli.add_command(start)
cli.add_command(block)
cli.add_command(unblock)
cli.add_command(is_blocked)

if __name__ == '__main__':
    cli()
