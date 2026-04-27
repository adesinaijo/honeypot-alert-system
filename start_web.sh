#!/bin/bash

# Load environment variables from the systemd environment file
set -a  # Automatically export all variables
source /etc/default/honeypot-web
set +a  # Disable auto-export

# Navigate to the project root directory
cd "/home/guesst/honeypot-alert-systems" || exit 1

# Activate the Python virtual environment
source "/venv/bin/activate"

# --- Set essential environment variables ---
export WEB_PORT="5000"  # Replace with your desired web port
export MONGO_URI="mongodb+srv://your_user:your_password@your_cluster.mongodb.net/honeypot_db?retryWrites=true&w=majority"
export DASHBOARD_PASSWORD="admin"
# --- End Set environment variables ---

# Run the web server (pointing to the correct app location)
exec gunicorn -w 4 --bind 0.0.0.0:${WEB_PORT} web.app:app
