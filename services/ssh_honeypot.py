# services/ssh_honeypot.py

import socket
import threading
import paramiko
import logging
import time # Import time for slight delay if needed

from services.base_honeypot import BaseHoneypot
from data.database import log_attack_event
# Import both alert sending functions
from core.alert_manager import send_email_alert, send_webhook_alert # Import send_webhook_alert


# Configure logging for Paramiko (optional, but helpful for debugging)
logging.basicConfig(level=logging.INFO)
paramiko.util.log_to_file("logs/paramiko.log")

# We need a host key for the SSH server emulation.
# If you don't have one, you can generate one with ssh-keygen.
# For a simple honeypot, we can generate one on the fly or use a dummy one.
# Using a dummy one is simpler for this example.
class AllowAllAuth(paramiko.ServerInterface):
    """A Paramiko ServerInterface that allows any authentication."""
    def __init__(self):
        self.event = threading.Event()
        self.username = None
        self.password = None


    def check_channel_request(self, kind, chanid):
        # We don't support shell or subsystem requests in this honeypot
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        """Called when a password authentication attempt is made."""
        print(f"[*] SSH Login Attempt: Username='{username}', Password='{password}'")

        # Capture credentials before signaling the event
        self.username = username
        self.password = password

        # Log the login attempt (we'll add credentials to event_details later)
        self.event.set() # Signal that an authentication attempt occurred

        # Always reject the authentication for a honeypot
        return paramiko.AUTH_FAILED

    # ... (check_auth_publickey, check_auth_interactive, check_auth_interactive_subservice remain the same) ...


class SSHHoneypot(BaseHoneypot):
    """Emulates an SSH server."""

    def __init__(self, host, port):
        super().__init__(host, port, name="SSHHoneypot")
        try:
            # Try to load an existing host key
            self.host_key = paramiko.RSAKey(filename='host_key.rsa')
        except paramiko.ssh_exception.SSHException:
            # If the key doesn't exist or is invalid, generate a new one
            print("[*] Generating new SSH host key...")
            self.host_key = paramiko.RSAKey.generate(2048)
            try:
                # Save the generated key
                self.host_key.write_private_key_file('host_key.rsa')
                print("[*] New SSH host key saved to host_key.rsa")
            except IOError:
                print("[!] Warning: Could not save host key to host_key.rsa")


    def handle_client(self, client_socket, client_address):
        """Handles incoming SSH connections."""
        client_ip = client_address[0]
        client_port = client_address[1]
        print(f"[*] Handling SSH client from {client_ip}:{client_port}")

        transport = paramiko.Transport(client_socket)
        try:
            # Advertise our fake server version
            transport.add_server_key(self.host_key)
            # Set our custom ServerInterface to handle authentication
            server = AllowAllAuth()
            transport.start_server(server=server)

            # Wait for an authentication attempt for a certain time
            server.event.wait(timeout=30) # Wait up to 30 seconds for an auth attempt

            # Prepare event details for logging and alerts
            event_details = {
                "service": self.name,
                "source_ip": client_ip,
                "source_port": client_port,
                "destination_port": self.port,
                "event_type": "connection_attempt_ssh", # Default event type
                "credentials": {} # Placeholder for credentials
                # Geolocation data will be added in log_attack_event
            }

            # If an authentication attempt happened, add credentials to event details and change type
            if server.event.is_set():
                 event_details["event_type"] = "ssh_login_attempt" # Change event type
                 if server.username:
                     event_details["credentials"]["username"] = server.username
                 if server.password:
                     event_details["credentials"]["password"] = server.password # Be cautious logging passwords!


            # Log the event (geolocation added here)
            log_attack_event(event_details)

            # --- Trigger Alerts ---
            # Email Alert - Only alert if an actual login attempt was made
            if server.event.is_set():
                subject = f"Honeypot Alert: SSH Login Attempt on Port {self.port}"
                body = f"Detected an SSH login attempt to the honeypot.\n\n" \
                       f"Source IP: {client_ip}\n" \
                       f"Source Port: {client_port}\n" \
                       f"Destination Port: {self.port}\n" \
                       f"Attempted Username: {server.username}\n" \
                       f"Attempted Password: {server.password} (Caution: Logging passwords is risky)"

                send_email_alert(subject, body)

                # Webhook Alert - Send the event_details dictionary as JSON payload
                send_webhook_alert(event_details) # <--- Call webhook alert
            # --- End Alert Triggers ---


        except Exception as e:
             print(f"[!] Error handling SSH client {client_address}: {e}")
             # Log the error as a potential malicious attempt or issue
             event_details = {
                 "service": self.name,
                 "source_ip": client_ip,
                 "source_port": client_port,
                 "destination_port": self.port,
                 "event_type": "ssh_error",
                 "details": str(e)
                 # Geolocation data will be added in log_attack_event
             }
             # Consider alerting on SSH errors too if they are frequent
             # send_email_alert(f"Honeypot SSH Error: {e}", f"Details: {event_details}")
             # send_webhook_alert({"error_event": event_details}) # Example webhook for errors
             log_attack_event(event_details)


        finally:
            # Close the connection
            print(f"[*] Closing SSH connection from {client_address}")
            # Give Paramiko a moment to clean up the transport gracefully
            time.sleep(0.1)
            transport.close()