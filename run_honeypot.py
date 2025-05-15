# run_honeypot.py

import sys
import os
import threading
import time
import logging

# Add the project root directory to the Python path
project_root = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, project_root)

# Import necessary modules and classes
from config import settings
from services.base_honeypot import BaseHoneypot
from services.http_honeypot import HTTPHoneypot
from services.ssh_honeypot import SSHHoneypot
from services.telnet_honeypot import TelnetHoneypot
from services.ftp_honeypot import FTPHoneypot # <-- Import FTP honeypot
from web.app import app
from data.database import init_logging


# --- Initialize logging as early as possible ---
init_logging()
# --- End logging initialization ---


# Define a list to hold honeypot threads
honeypot_threads = []

# --- Function to run the Flask web server ---
def run_flask_app():
    """Runs the Flask application."""
    logging.info(f"Starting Flask web server on port {settings.WEB_PORT}...")
    print(f"[*] Starting Flask web server on port {settings.WEB_PORT}...")
    try:
        app.run(host='0.0.0.0', port=settings.WEB_PORT, debug=settings.FLASK_DEBUG)
    except Exception as e:
        logging.error(f"Failed to start Flask web server: {e}", exc_info=True)
        print(f"[!] Failed to start Flask web server: {e}")


# --- Main execution block ---
if __name__ == "__main__":
    print("[*] Starting Honeypot Alert System...")

    listen_host = "0.0.0.0"

    print(f"[*] Listening on {listen_host} for ports: {settings.HONEYPOT_PORTS} and web on port {settings.WEB_PORT}")

    for port in settings.HONEYPOT_PORTS:
        honeypot_instance = None
        if port == 80 or port == 443:
             honeypot_instance = HTTPHoneypot(listen_host, port)
             print(f"[*] HTTPHoneypot listening on {listen_host}:{port}")
        elif port == 22:
             honeypot_instance = SSHHoneypot(listen_host, port)
             print(f"[*] SSHHoneypot listening on {listen_host}:{port}")
        elif port == 23:
             honeypot_instance = TelnetHoneypot(listen_host, port)
             print(f"[*] TelnetHoneypot listening on {listen_host}:{port}")
        elif port == 21: # <-- Add FTP port check
             honeypot_instance = FTPHoneypot(listen_host, port)
             print(f"[*] FTPHoneypot listening on {listen_host}:{port}")
        # Add more elif blocks here for other honeypot types based on port

        if honeypot_instance:
            honeypot_thread = threading.Thread(target=honeypot_instance.start)
            honeypot_threads.append(honeypot_thread)
            honeypot_thread.daemon = True
            honeypot_thread.start()
        else:
            print(f"[!] No specific honeypot implementation for port {port}. Skipping.")
            logging.warning(f"No specific honeypot implementation for port {port}. Skipping.")


    flask_thread = threading.Thread(target=run_flask_app)
    flask_thread.daemon = True
    flask_thread.start()

    print("[*] Honeypot services and web server started.")
    print(f"[*] Listening on {listen_host} for ports: {settings.HONEYPOT_PORTS} and web on port {settings.WEB_PORT}")
    print("[*] Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down Honeypot Alert System.")
        logging.info("Honeypot Alert System shutting down.")
        sys.exit(0)