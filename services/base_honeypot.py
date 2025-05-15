# services/base_honeypot.py

import socket
import threading
from data.database import log_attack_event

class BaseHoneypot(threading.Thread):
    """Base class for all honeypot services."""

    def __init__(self, host, port, name="GenericHoneypot"):
        # Call the parent class (threading.Thread) constructor
        super().__init__()
        self.host = host
        self.port = port
        self.name = name
        self._stop_event = threading.Event() # Event to signal when to stop the thread

    def run(self):
        """This method is called when the thread starts."""
        print(f"[*] {self.name} listening on {self.host}:{self.port}")
        self._start_listening()

    def _start_listening(self):
        """Starts the network listener."""
        # Create a socket
        # socket.AF_INET: use IPv4
        # socket.SOCK_STREAM: use TCP
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Allow the socket to reuse the address and port
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            # Bind the socket to the host and port
            server_socket.bind((self.host, self.port))
            # Listen for incoming connections (allow up to 5 queued connections)
            server_socket.listen(5)

            while not self._stop_event.is_set():
                # Accept incoming connections
                # accept() returns a new socket object representing the connection
                # and the address of the client
                try:
                    client_socket, client_address = server_socket.accept()
                    client_ip = client_address[0]
                    client_port = client_address[1]
                    print(f"[*] Connection from {client_ip}:{client_port} to {self.name}")

                    # Log the connection attempt
                    event_details = {
                        "service": self.name,
                        "source_ip": client_ip,
                        "source_port": client_port,
                        "destination_port": self.port,
                        "event_type": "connection_attempt"
                    }
                    log_attack_event(event_details)

                    # Handle the client connection in a separate thread
                    # This prevents blocking the main listening loop
                    client_handler = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
                    client_handler.start()

                except socket.timeout:
                    # Handle timeout if needed
                    pass
                except Exception as e:
                    print(f"[!] Error accepting connection: {e}")


        except Exception as e:
            print(f"[!] Failed to bind {self.name} to {self.host}:{self.port}: {e}")

        finally:
            server_socket.close()
            print(f"[*] {self.name} listening stopped.")


    def handle_client(self, client_socket, client_address):
        """Handle data from a connected client."""
        # This is where specific service logic will go in subclasses
        print(f"[*] Handling client from {client_address}")
        try:
            # Close the connection immediately for the base class
            client_socket.close()
        except Exception as e:
            print(f"[!] Error handling client {client_address}: {e}")

    def stop(self):
        """Signals the honeypot to stop listening."""
        print(f"[*] Stopping {self.name}...")
        self._stop_event.set()
        # Create a dummy connection to unblock the accept() call
        try:
            socket.create_connection((self.host, self.port), timeout=1)
        except (ConnectionRefusedError, OSError):
            pass # Expected if the socket is already closed