import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv
import os


# Load environment variables from .env file
load_dotenv()


def send_email_alert(subject: str, body: str):
    """Send an email notification using Gmail SMTP server."""
    sender_email = os.getenv('GMAIL_USERNAME')
    app_password = os.getenv('GMAIL_APP_PASSWORD')
    receiver_email = os.getenv('ALERT_EMAIL')

    # Create the email message
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Set up the SMTP server and send the email
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, app_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
            print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {str(e)}")

def send_block_alert(ip: str):
    """Sends an email alert when an IP is blocked."""
    subject = f"Alert: IP {ip} Blocked"
    body = f"The IP address {ip} has been blocked."

    send_email_alert(subject, body)

def send_unblock_alert(ip: str):
    """Sends an email alert when an IP is unblocked."""
    subject = f"Alert: IP {ip} Unblocked"
    body = f"The IP address {ip} has been unblocked."

    send_email_alert(subject, body)

def send_attack_alert(src_ip: str, syn_count: int, threshold: int, window: int):
    """Sends an email alert when a SYN flood attack is detected."""
    subject = f"Alert: SYN Flood Attack Detected from {src_ip}"
    body = (
        f"A SYN flood attack has been detected from IP: {src_ip}\n\n"
        f"Details:\n"
        f"Suspicious IP: {src_ip}\n"
        f"Number of SYN packets: {syn_count}\n"
        f"Threshold exceeded: {threshold} SYN packets within {window} seconds\n"
    )

    send_email_alert(subject, body)
