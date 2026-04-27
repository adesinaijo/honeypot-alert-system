# web/run_web.py

import sys
import os
import logging

# Add the project root directory to the Python path
# Assumes run_web.py is in PROJECT_ROOT/web/
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
sys.path.insert(0, project_root)

# Import the Flask app instance
from web.app import app
from data.database import init_logging # Import logging initialization
from config import settings # Import settings to check if logging is needed

# --- Initialize logging if it hasn't been already ---
# This is important if run_web.py is started independently
# The check in init_logging prevents re-initialization
init_logging()
# --- End logging initialization ---


# This script itself doesn't run app.run().
# It just provides the 'app' object for a WSGI server like Gunicorn.
# Gunicorn will look for a callable named 'app' in this module.

logging.info("web/run_web.py loaded, ready for WSGI server.")
print("[*] web/run_web.py loaded, ready for WSGI server.")


# Example of how you *wouldn't* run this file directly anymore:
# if __name__ == "__main__":
#     # This block is often used in development for quick testing,
#     # but Gunicorn won't execute it.
#     print("This block is typically skipped when using Gunicorn.")
#     # You would still run run_honeypot.py separately.
#     # app.run(host='0.0.0.0', port=settings.WEB_PORT, debug=settings.FLASK_DEBUG)