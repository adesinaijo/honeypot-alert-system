# web/app.py

from flask import Flask, render_template, jsonify, request
import sys
import os
from bson.objectid import ObjectId
import logging

# --- Import Flask-HTTPAuth ---
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash
# --- End Flask-HTTPAuth Imports ---


# Add the project root directory to the Python path (keep as is)
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
sys.path.insert(0, project_root)

# Import data retrieval and logging initialization functions
# Ensure get_recent_attack_events and get_all_attack_events can accept 'service', 'source_ip', 'source_port' filters
from data.database import get_recent_attack_events, get_all_attack_events, init_logging
from config import settings


# --- Initialize logging ---
# Check if logging is already configured
if not logging.getLogger().handlers:
    init_logging()


app = Flask(__name__)

# --- Flask-HTTPAuth Setup ---
auth = HTTPBasicAuth()

users = {
    settings.DASHBOARD_USERNAME: generate_password_hash(settings.DASHBOARD_PASSWORD)
}

@auth.verify_password
def verify_password(username, password):
    if username in users and check_password_hash(users.get(username), password):
        logging.info(f"Dashboard login successful for user: {username}")
        return username
    logging.warning(f"Dashboard login failed for user: {username}")
    return None

@auth.error_handler
def auth_error(status):
    logging.warning(f"Authentication error with status: {status}")
    return "Authentication Required", 401

# --- End Flask-HTTPAuth Setup ---


# Route for the main dashboard page
@app.route('/')
@auth.login_required
def dashboard():
    return render_template('index.html')

# API endpoint to get recent attack data
@app.route('/data/recent')
@auth.login_required
def get_recent_data():
    """Returns recent attack events as JSON, with optional filtering and polling."""
    since_id_str = request.args.get('since_id')
    service_filter = request.args.get('service')
    # --- Get new filters from query parameters --- # <-- Add these lines
    ip_filter = request.args.get('source_ip')
    port_filter_str = request.args.get('source_port')
    # -------------------------------------------

    # print(f"[*] Flask /data/recent accessed. since_id_str: {since_id_str}, service_filter: {service_filter}, ip_filter: {ip_filter}, port_filter_str: {port_filter_str}") # Debug print


    query_filter = {}
    filter_clauses = [] # Use a list to build multiple conditions

    # Add _id filter for polling
    if since_id_str:
        try:
            since_id_obj = ObjectId(since_id_str)
            filter_clauses.append({"_id": {"$gt": since_id_obj}})
        except Exception as e:
            logging.warning(f"[!] Invalid since_id format: {since_id_str} - {e}")

    # Add service filter
    if service_filter and service_filter != 'All':
         filter_clauses.append({"service": service_filter})

    # --- Add new filters to filter_clauses --- # <-- Add this section
    if ip_filter:
         filter_clauses.append({"source_ip": ip_filter})

    if port_filter_str:
         try:
              port_filter_int = int(port_filter_str)
              filter_clauses.append({"source_port": port_filter_int})
         except ValueError:
              logging.warning(f"[!] Invalid source_port format: {port_filter_str}")
    # ----------------------------------------

    # Combine filter clauses using $and if there are multiple
    if filter_clauses:
         # If there's only one clause, use it directly. Otherwise, combine with $and.
         query_filter = filter_clauses[0] if len(filter_clauses) == 1 else {"$and": filter_clauses}


    recent_events = []
    # Call the database function with the constructed query_filter
    if query_filter:
         # If we have any filter, get events matching the filter, sorted by ID ascending for polling
         recent_events = get_recent_attack_events(query_filter=query_filter, sort_order=1)
    else:
         # If no filters applied, get the latest N events
         recent_events = get_recent_attack_events(limit=20)


    # print(f"[*] get_recent_attack_events returned {len(recent_events)} events.") # Debug print
    return jsonify(recent_events)


# API endpoint to get all attack data
@app.route('/data/all')
@auth.login_required
def get_all_data():
    """Returns all attack events as JSON, with optional filtering."""
    service_filter = request.args.get('service')
    # --- Get new filters from query parameters --- # <-- Add these lines
    ip_filter = request.args.get('source_ip')
    port_filter_str = request.args.get('source_port')
    # -------------------------------------------

    # print(f"[*] Flask /data/all accessed. service_filter: {service_filter}, ip_filter: {ip_filter}, port_filter_str: {port_filter_str}") # Debug print

    # --- Build filter clauses --- # <-- Add this section (similar to get_recent_data)
    filter_clauses = []

    if service_filter and service_filter != 'All':
         filter_clauses.append({"service": service_filter})

    if ip_filter:
         filter_clauses.append({"source_ip": ip_filter})

    if port_filter_str:
         try:
              port_filter_int = int(port_filter_str)
              filter_clauses.append({"source_port": port_filter_int})
         except ValueError:
              logging.warning(f"[!] Invalid source_port format: {port_filter_str}")

    # Combine filter clauses
    query_filter = filter_clauses[0] if len(filter_clauses) == 1 else {"$and": filter_clauses} if filter_clauses else {}
    # --- End Build filter clauses ---

    # Call the database function with the constructed query_filter
    all_events = get_all_attack_events(query_filter=query_filter)

    # print(f"[*] get_all_data returned {len(all_events)} events.") # Debug print

    return jsonify(all_events)

# if __name__ == '__main__': block is removed