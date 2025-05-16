# config/settings.py

import os
import logging

# --- Database Settings ---
# Read MongoDB URI from environment variable or use a default (less secure for default)
# It's highly recommended to set the MONGO_URI environment variable.
DATABASE_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
DATABASE_NAME = os.getenv('MONGO_DB_NAME', 'honeypot_db') # Read DB name from env
DATABASE_ENABLED = os.getenv('DATABASE_ENABLED', 'True').lower() == 'true' # Read DB enabled state

# --- Honeypot Settings ---
# Ports the honeypot listener will bind to
# Can be a comma-separated string in env var, or a list in settings file
HONEYPOT_PORTS_STR = os.getenv('HONEYPOT_PORTS', '80,22,23,21') # Default to common ports
try:
    HONEYPOT_PORTS = [int(port.strip()) for port in HONEYPOT_PORTS_STR.split(',')]
except ValueError:
    logging.error(f"Invalid value for HONEYPOT_PORTS environment variable: {HONEYPOT_PORTS_STR}. Using default ports.")
    HONEYPOT_PORTS = [80, 22, 23, 21] # Fallback to default list if env var is invalid


# --- Dashboard Settings ---
WEB_PORT = int(os.getenv('WEB_PORT', 5000)) # Read web port from env, default to 5000
FLASK_DEBUG = os.getenv('FLASK_DEBUG', 'False').lower() == 'true' # Read debug state from env

# Dashboard Authentication
# Read dashboard username and password from environment variables
# It's CRITICAL to set these environment variables and use strong, unique credentials.
DASHBOARD_USERNAME = os.getenv('DASHBOARD_USERNAME', 'admin') # Default is insecure, CHANGE THIS IN PROD
DASHBOARD_PASSWORD = os.getenv('DASHBOARD_PASSWORD', 'password123') # Default is insecure, CHANGE THIS IN PROD

# --- Alerting Settings ---
ALERTING_ENABLED = os.getenv('ALERTING_ENABLED', 'True').lower() == 'true' # Read alerting enabled state

# Email Alerts
EMAIL_ALERTS_ENABLED = os.getenv('EMAIL_ALERTS_ENABLED', 'False').lower() == 'true' # Read email alerts enabled state
# Read email credentials and settings from environment variables
# Set these environment variables if EMAIL_ALERTS_ENABLED is True
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD') # Use an App Password if using Gmail or similar
EMAIL_SMTP_SERVER = os.getenv('EMAIL_SMTP_SERVER', 'smtp.gmail.com') # Default SMTP server
EMAIL_SMTP_PORT = int(os.getenv('EMAIL_SMTP_PORT', 587)) # Default SMTP port (TLS)
EMAIL_RECIPIENTS = os.getenv('EMAIL_RECIPIENTS') # Comma-separated email addresses

# Webhook Alerts
WEBHOOK_ALERTS_ENABLED = os.getenv('WEBHOOK_ALERTS_ENABLED', 'False').lower() == 'true' # Read webhook alerts enabled state
# Read webhook URL from environment variable
# Set this environment variable if WEBHOOK_ALERTS_ENABLED is True
WEBHOOK_URL = os.getenv('WEBHOOK_URL')

# Geo-location Settings
# Read Geo-location API Key from environment variable
# Set this environment variable if you use a paid service requiring an API key
GEOLOCATION_API_KEY = os.getenv('GEOLOCATION_API_KEY')
# Geo-location API Endpoint (if using a service other than ipinfo.io default)
GEOLOCATION_API_URL = os.getenv('GEOLOCATION_API_URL', 'https://ipinfo.io/{}/json')


# --- Additional Settings (Optional) ---
# Polling interval for the dashboard list in milliseconds
DASHBOARD_POLLING_INTERVAL_MS = int(os.getenv('DASHBOARD_POLLING_INTERVAL_MS', 5000))

# Note: It's good practice to validate that required environment variables are set
# if the corresponding feature is enabled (e.g., check if EMAIL_ADDRESS and EMAIL_PASSWORD
# are set if EMAIL_ALERTS_ENABLED is True). For this step, we'll just read them.

# Example check (can be added later):
# if ALERTING_ENABLED and EMAIL_ALERTS_ENABLED and (not EMAIL_ADDRESS or not EMAIL_PASSWORD or not EMAIL_RECIPIENTS):
#     logging.warning("Email alerts are enabled but required environment variables (EMAIL_ADDRESS, EMAIL_PASSWORD, EMAIL_RECIPIENTS) are not set.")