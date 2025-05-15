# core/alert_manager.py

import smtplib
from email.mime.text import MIMEText
import logging
import requests # We'll use this later for webhooks

from config import settings

def send_email_alert(subject, body):
    """Sends an email alert if email alerts are enabled."""
    if not settings.ALERT_EMAIL_ENABLED:
        logging.debug("Email alerts are disabled.")
        return

    sender_email = settings.ALERT_EMAIL_USERNAME
    receiver_email = settings.ALERT_EMAIL_ADDRESS
    smtp_server = settings.ALERT_EMAIL_SMTP_SERVER
    smtp_port = settings.ALERT_EMAIL_SMTP_PORT
    password = settings.ALERT_EMAIL_PASSWORD

    # Create the email message
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = receiver_email

    try:
        # Connect to the SMTP server
        # Use smtplib.SMTP_SSL(smtp_server, smtp_port) for SSL (port 465)
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Secure the connection with TLS (usually for port 587)
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, msg.as_string())

        logging.info(f"Email alert sent: '{subject}' to {receiver_email}")

    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")

def send_webhook_alert(payload):
    """Sends a webhook alert if webhook alerts are enabled."""
    if not settings.ALERT_WEBHOOK_ENABLED:
        logging.debug("Webhook alerts are disabled.")
        return

    webhook_url = settings.ALERT_WEBHOOK_URL

    try:
        # Send a POST request to the webhook URL
        response = requests.post(webhook_url, json=payload, timeout=10) # Send payload as JSON
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

        logging.info(f"Webhook alert sent to {webhook_url}")

    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to send webhook alert to {webhook_url}: {e}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during webhook alert: {e}")