# services/http_honeypot.py

from services.base_honeypot import BaseHoneypot
from data.database import log_attack_event
from core.alert_manager import send_email_alert, send_webhook_alert # Ensure both are imported
from datetime import datetime # Import datetime for timestamp

class HTTPHoneypot(BaseHoneypot):
    """Emulates a simple HTTP server."""

    def __init__(self, host, port):
        super().__init__(host, port, name="HTTPHoneypot")
        # Basic HTTP response to send
        self.http_response = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.18 (Ubuntu)\r\nContent-Length: 12\r\n\r\nHello World!"

    def handle_client(self, client_socket, client_address):
        """Handles incoming HTTP connections."""
        client_ip = client_address[0]
        client_port = client_address[1]

        print(f"[*] Received connection from {client_ip}:{client_port} on port {self.port}") # Keep this print

        # --- Log the initial connection attempt (regardless of data) ---
        connection_event_details = {
            "service": self.name,
            "source_ip": client_ip,
            "source_port": client_port,
            "destination_port": self.port,
            "event_type": "connection_attempt",
            "timestamp": datetime.now().isoformat() # Add timestamp for consistency
        }
        log_attack_event(connection_event_details) # Log the connection attempt

        # --- Trigger Alerts for the initial connection attempt ---
        # (You can decide if you want alerts for just connections or only when data is received)
        # For now, let's trigger alerts for any connection attempt
        subject = f"Honeypot Alert: HTTP Connection Attempt on Port {self.port}"
        body = f"Detected a connection attempt to the HTTP honeypot.\n\n" \
               f"Source IP: {client_ip}\n" \
               f"Source Port: {client_port}\n" \
               f"Destination Port: {self.port}"
        send_email_alert(subject, body)
        send_webhook_alert(connection_event_details) # Send connection details to webhook
        # --- End Alerts for Connection Attempt ---


        try:
            # Receive data from the client (e.g., the HTTP request)
            # We'll try to receive up to 1024 bytes
            client_socket.settimeout(5) # Optional: Set a timeout for receiving data
            data = client_socket.recv(1024)

            if data:
                request_data = data.decode('utf-8', errors='ignore').strip()

                print(f"[*] Received data from {client_ip}:{client_port}:\n---\n{request_data}\n---")

                # --- Log the data received event (if data was sent) ---
                data_event_details = {
                    "service": self.name,
                    "source_ip": client_ip,
                    "source_port": client_port,
                    "destination_port": self.port,
                    "event_type": "data_received",
                    "timestamp": datetime.now().isoformat(), # Add timestamp
                    "data": request_data
                }
                log_attack_event(data_event_details) # Log the data received event

                # --- Trigger Alerts for data received (Optional - avoid duplicate alerts) ---
                # You might want to comment these out if you already alert on connection attempt
                # or modify them to indicate data was received after the connection.
                # Example modification:
                # subject_data = f"Honeypot Alert: HTTP Data Received on Port {self.port}"
                # body_data = f"Data received from {client_ip}:\n---\n{request_data}\n---"
                # send_email_alert(subject_data, body_data)
                # send_webhook_alert(data_event_details)
                # --- End Alerts for data received ---


                # Send a fake HTTP response
                client_socket.sendall(self.http_response)

        except socket.timeout: # Catch timeout specifically
             print(f"[*] No data received from {client_ip}:{client_port} within timeout.")
        except Exception as e:
            print(f"[!] Error handling HTTP client {client_address}: {e}")
        finally:
            # Close the connection
            client_socket.close()
            print(f"[*] Closed connection from {client_address}")