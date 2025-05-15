# services/telnet_honeypot.py

from services.base_honeypot import BaseHoneypot
from data.database import log_attack_event
from core.alert_manager import send_email_alert, send_webhook_alert
import socket
import time
import logging

class TelnetHoneypot(BaseHoneypot):
    """Emulates a simple Telnet server to capture logins."""

    def __init__(self, host, port):
        super().__init__(host, port, name="TelnetHoneypot")
        # Basic Telnet banner and login prompt
        self.telnet_banner = b"\r\nWelcome to the server!\r\nLogin: "
        self.password_prompt = b"Password: "
        self.login_failed_message = b"\r\nLogin failed\r\n"
        self.close_message = b"\r\nConnection closed.\r\n"

    def handle_client(self, client_socket, client_address):
        """Handles incoming Telnet connections."""
        client_ip = client_address[0]
        client_port = client_address[1]

        print(f"[*] Received connection from {client_ip}:{client_port} on port {self.port}")

        # --- Log the initial connection attempt ---
        connection_event_details = {
            "service": self.name,
            "source_ip": client_ip,
            "source_port": client_port,
            "destination_port": self.port,
            "event_type": "connection_attempt",
            # Timestamp is added by log_attack_event
        }
        log_attack_event(connection_event_details)

        # --- Trigger Alerts for the initial connection attempt (Optional) ---
        # You might want to adjust alerts later if you only want alerts on login attempts
        subject = f"Honeypot Alert: Telnet Connection Attempt on Port {self.port}"
        body = f"Detected a connection attempt to the Telnet honeypot.\n\n" \
               f"Source IP: {client_ip}\n" \
               f"Source Port: {client_port}\n" \
               f"Destination Port: {self.port}"
        send_email_alert(subject, body)
        send_webhook_alert(connection_event_details)
        # --- End Alerts ---


        try:
            # Send the initial Telnet banner and login prompt
            client_socket.sendall(self.telnet_banner)

            # Receive username
            client_socket.settimeout(10) # Set a timeout for receiving data
            username_data = b''
            # Read until newline or timeout
            while b'\n' not in username_data and b'\r' not in username_data:
                 chunk = client_socket.recv(1) # Read character by character
                 if not chunk:
                      break # Connection closed
                 username_data += chunk

            username = username_data.decode('ascii', errors='ignore').strip()
            print(f"[*] Received Telnet username from {client_ip}:{client_port}: {username}")


            # Send password prompt
            client_socket.sendall(self.password_prompt)

            # Receive password
            password_data = b''
            # Read until newline or timeout
            while b'\n' not in password_data and b'\r' not in password_data:
                 chunk = client_socket.recv(1) # Read character by character
                 if not chunk:
                      break # Connection closed
                 password_data += chunk

            password = password_data.decode('ascii', errors='ignore').strip()
            print(f"[*] Received Telnet password from {client_ip}:{client_port}: {password}")

            # --- Log the login attempt event ---
            login_event_details = {
                "service": self.name,
                "source_ip": client_ip,
                "source_port": client_port,
                "destination_port": self.port,
                "event_type": "telnet_login_attempt", # Specific event type
                "credentials": {
                    "username": username,
                    "password": password # Captured credentials
                }
                # Timestamp is added by log_attack_event
            }
            log_attack_event(login_event_details)

            # --- Trigger Alerts for the login attempt ---
            subject = f"Honeypot Alert: Telnet Login Attempt on Port {self.port}"
            body = f"Detected a Telnet login attempt.\n\n" \
                   f"Source IP: {client_ip}\n" \
                   f"Source Port: {client_port}\n" \
                   f"Destination Port: {self.port}\n" \
                   f"Attempted Username: {username}\n" \
                   f"Attempted Password: {password}\n" \
                   f"(Caution: Displaying credentials is risky)"
            send_email_alert(subject, body)
            send_webhook_alert(login_event_details)
            # --- End Alerts ---


            # Send a fake login failed message and close
            client_socket.sendall(self.login_failed_message)
            time.sleep(0.5) # Simulate a small delay
            client_socket.sendall(self.close_message)


        except socket.timeout:
             print(f"[*] Timeout receiving data from {client_ip}:{client_port}")
        except Exception as e:
            print(f"[!] Error handling Telnet client {client_address}: {e}")
            logging.error(f"Error handling Telnet client {client_address}: {e}", exc_info=True) # Log the exception
        finally:
            # Close the connection
            client_socket.close()
            print(f"[*] Closed connection from {client_address}")