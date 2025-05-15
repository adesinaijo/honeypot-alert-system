# services/ftp_honeypot.py

from services.base_honeypot import BaseHoneypot
from data.database import log_attack_event
from core.alert_manager import send_email_alert, send_webhook_alert
import socket
import time
import logging
import re # Import regex for parsing commands

class FTPHoneypot(BaseHoneypot):
    """Emulates a simple FTP server to capture logins."""

    def __init__(self, host, port):
        super().__init__(host, port, name="FTPHoneypot")
        # Basic FTP responses (codes and messages)
        self.welcome_message = b"220 Welcome to the Fake FTP Service\r\n"
        self.user_ok_message = b"331 User accepted, provide password\r\n"
        self.login_failed_message = b"530 Login incorrect\r\n"
        self.generic_error = b"500 Syntax error, command unrecognized\r\n"
        self.goodbye_message = b"221 Goodbye.\r\n"

    def handle_client(self, client_socket, client_address):
        """Handles incoming FTP connections."""
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
        subject = f"Honeypot Alert: FTP Connection Attempt on Port {self.port}"
        body = f"Detected a connection attempt to the FTP honeypot.\n\n" \
               f"Source IP: {client_ip}\n" \
               f"Source Port: {client_port}\n" \
               f"Destination Port: {self.port}"
        send_email_alert(subject, body)
        send_webhook_alert(connection_event_details)
        # --- End Alerts ---

        captured_username = None
        captured_password = None

        try:
            # Send the initial FTP welcome banner
            client_socket.sendall(self.welcome_message)
            client_socket.settimeout(15) # Set a timeout for client inactivity

            # Read commands in a loop
            while True:
                 # Read data from the client
                 # FTP commands are typically line-oriented
                 data = client_socket.recv(1024)
                 if not data:
                      break # Connection closed by client

                 commands = data.decode('ascii', errors='ignore').splitlines()

                 for command_line in commands:
                     command_line = command_line.strip()
                     if not command_line:
                          continue

                     print(f"[*] Received FTP command from {client_ip}:{client_port}: {command_line}")
                     logging.debug(f"Received FTP command: {command_line} from {client_ip}:{client_port}")

                     # --- Process Commands ---
                     # We are primarily interested in USER and PASS
                     user_match = re.match(r"USER\s+(.+)", command_line, re.IGNORECASE)
                     pass_match = re.match(r"PASS\s+(.+)", command_line, re.IGNORECASE)
                     quit_match = re.match(r"QUIT", command_line, re.IGNORECASE) # Handle QUIT command


                     if user_match:
                         captured_username = user_match.group(1).strip()
                         print(f"[*] Captured FTP username: {captured_username}")
                         client_socket.sendall(self.user_ok_message) # Respond with 331 User accepted
                     elif pass_match:
                         captured_password = pass_match.group(1).strip()
                         print(f"[*] Captured FTP password: {captured_password}")

                         # --- Log the login attempt event ---
                         login_event_details = {
                             "service": self.name,
                             "source_ip": client_ip,
                             "source_port": client_port,
                             "destination_port": self.port,
                             "event_type": "ftp_login_attempt", # Specific event type
                             "credentials": {
                                 "username": captured_username if captured_username is not None else "N/A",
                                 "password": captured_password # Captured password
                             }
                             # Timestamp is added by log_attack_event
                         }
                         log_attack_event(login_event_details)

                         # --- Trigger Alerts for the login attempt ---
                         subject = f"Honeypot Alert: FTP Login Attempt on Port {self.port}"
                         body = f"Detected an FTP login attempt.\n\n" \
                                f"Source IP: {client_ip}\n" \
                                f"Source Port: {client_port}\n" \
                                f"Destination Port: {self.port}\n" \
                                f"Attempted Username: {login_event_details['credentials']['username']}\n" \
                                f"Attempted Password: {login_event_details['credentials']['password']}\n" \
                                f"(Caution: Displaying credentials is risky)"
                         send_email_alert(subject, body)
                         send_webhook_alert(login_event_details)
                         # --- End Alerts ---

                         client_socket.sendall(self.login_failed_message) # Respond with 530 Login incorrect
                         # After a login attempt, we might want to close the connection
                         break # Exit the while loop to close connection

                     elif quit_match:
                         client_socket.sendall(self.goodbye_message) # Respond with 221 Goodbye
                         break # Exit the while loop to close connection

                     else:
                         # Respond to other commands with a generic error
                         client_socket.sendall(self.generic_error)


                 if captured_password is not None or quit_match:
                      break # Break outer loop after processing login or quit

        except socket.timeout:
             print(f"[*] Timeout during FTP session from {client_ip}:{client_port}")
        except Exception as e:
            print(f"[!] Error handling FTP client {client_address}: {e}")
            logging.error(f"Error handling FTP client {client_address}: {e}", exc_info=True) # Log the exception
        finally:
            # Close the connection
            client_socket.close()
            print(f"[*] Closed connection from {client_address}")