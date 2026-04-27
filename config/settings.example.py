# config/settings.example.py
# Copy this file to settings.py and fill in your actual values
# DO NOT commit settings.py to version control

# --- General Settings ---
DEBUG = False
LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR

# --- Honeypot Service Ports ---
SSH_PORT = 2222
HTTP_PORT = 8080
FTP_PORT = 2121
TELNET_PORT = 2323

# --- MongoDB Settings ---
MONGO_URI = "mongodb://localhost:27017/"
MONGO_DB_NAME = "honeypot_db"

# --- Email Alert Settings ---
ALERT_EMAIL_ENABLED = True
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "your_email@gmail.com"
SMTP_PASSWORD = "your_app_password_here"
ALERT_RECIPIENT = "recipient@gmail.com"

# --- Geolocation Settings ---
GEOLOCATION_ENABLED = True
GEOLOCATION_API_URL = "http://ip-api.com/json/"  # Must be HTTP not HTTPS on free tier

# --- Web Dashboard Settings ---
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
SECRET_KEY = "replace_with_a_strong_random_secret_key"
