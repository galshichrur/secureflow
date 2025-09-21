import platform
import subprocess
import click
import alert


class IPBlocker:
    """Manages blocking and unblocking of IP addresses using operating system firewall rules."""

    def __init__(self):
        self.system: str = platform.system()  # Detect OS

    def block_ip(self, ip: str) -> None:
        """Blocks a specified IP address using firewall rules."""
        click.secho(f"Blocking IP: {ip}", fg="yellow")
        if self.system == "Linux":
            command = f"sudo iptables -A INPUT -s {ip} -j DROP"
        elif self.system == "Windows":
            command = f"netsh advfirewall firewall add rule name='Block {ip}' dir=in action=block remoteip={ip}"
        else:
            click.secho(f"Unsupported OS: {self.system}", fg="yellow")
            return

        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            click.secho(f"Blocked IP: {ip}", fg="green")
            alert.send_block_alert(ip)
        else:
            click.secho(f"Failed to block {ip}: {result.stderr}", fg="red")

    def unblock_ip(self, ip: str) -> None:
        """Unblocks a previously blocked IP address."""
        if self.system == "Linux":
            command = f"sudo iptables -D INPUT -s {ip} -j DROP"
        elif self.system == "Windows":
            command = f"netsh advfirewall firewall delete rule name='Block {ip}'"
        else:
            click.secho(f"Unsupported OS: {self.system}", fg="yellow")
            return

        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            click.secho(f"Unblocked IP: {ip}", fg="green")
            alert.send_unblock_alert(ip)
        else:
            click.secho(f"Failed to unblock {ip}: {result.stderr}", fg="red")

    def is_ip_blocked(self, ip: str) -> bool:
        """Checks if an IP address is currently blocked."""
        if self.system == "Linux":
            command = "sudo iptables -L INPUT -v -n"
        elif self.system == "Windows":
            command = "netsh advfirewall firewall show rule name=all"
        else:
            click.secho(f"Unsupported OS: {self.system}", fg="yellow")
            return False

        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return ip in result.stdout
