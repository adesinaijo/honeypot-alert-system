# data/database.py

import logging
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure
from config import settings
from core.geolocation import get_geolocation
import os
import sys
from bson.objectid import ObjectId # Import ObjectId for querying
# --- Import datetime if needed for potential date object handling,
#     or ensuring timestamps are datetime objects before logging.
from datetime import datetime
# --- End datetime Import ---


# MongoDB client and database initialization
client = None
db = None

# Function to initialize logging
def init_logging():
    """Initializes logging to a file within the project's logs directory."""
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    log_file_path = os.path.join(project_root, 'logs', 'honeypot.log')

    log_dir = os.path.dirname(log_file_path)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    logging.basicConfig(filename=log_file_path, level=logging.INFO, filemode='a',
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # Use root logger for initial setup messages
    logging.getLogger().info("Logging initialized.")


# Initialize MongoDB connection if database is enabled
if settings.DATABASE_ENABLED:
    try:
        # Ensure init_logging has been called before logging connection status
        if not logging.getLogger().handlers:
             init_logging()

        logging.info(f"Attempting to connect to MongoDB: {settings.DATABASE_URI}, Database: {settings.DATABASE_NAME}")
        print(f"[*] Attempting to connect to MongoDB: {settings.DATABASE_URI}, Database: {settings.DATABASE_NAME}")

        client = MongoClient(settings.DATABASE_URI, serverSelectionTimeoutMS=10000)
        client.admin.command('ismaster') # Check connection
        db = client[settings.DATABASE_NAME]
        logging.info(f"Successfully connected to MongoDB: {settings.DATABASE_URI}, Database: {settings.DATABASE_NAME}")
        print(f"[*] Successfully connected to MongoDB: {settings.DATABASE_URI}, Database: {settings.DATABASE_NAME}")

    except ConnectionFailure as e:
        logging.error(f"Failed to connect to MongoDB at {settings.DATABASE_URI}: {e}")
        client = None # Ensure client is None if connection fails
        db = None
        logging.warning("Database logging is enabled but connection failed. Falling back to file logging.")
        print(f"[!] Failed to connect to MongoDB: {e}")

    except Exception as e:
         logging.error(f"An unexpected error occurred during MongoDB connection: {e}", exc_info=True) # Log traceback
         client = None
         db = None
         logging.warning("Database logging is enabled but an unexpected error occurred. Falling back to file logging.")
         print(f"[!] An unexpected error occurred during MongoDB connection: {e}")


def log_attack_event(event_details):
    """Logs a detected attack event to MongoDB or file, with optional geo-location."""
    # Use a dedicated logger or include the process/thread ID if running multi-process
    logging.info(f"log_attack_event called for event: {event_details.get('event_type', 'N/A')} from {event_details.get('source_ip', 'N/A')}")
    print(f"[*] log_attack_event called for event: {event_details.get('event_type', 'N/A')} from {event_details.get('source_ip', 'N/A')}")

    # Get geo-location if enabled and IP is available
    source_ip = event_details.get("source_ip")
    geolocation_data = None
    if source_ip:
        geolocation_data = get_geolocation(source_ip) # This function handles private IPs and API calls

    # Add geolocation data to event details if available
    if geolocation_data:
         event_details["geolocation"] = geolocation_data
         if geolocation_data.get("country") != "Private IP":
              logging.info(f"Geo-location added: {geolocation_data.get('city', 'N/A')}, {geolocation_data.get('country', 'N/A')}")
              print(f"[*] Geo-location added: {geolocation_data.get('city', 'N/A')}, {geolocation_data.get('country', 'N/A')}")
         else:
             logging.info(f"Geo-location skipped for private IP: {source_ip}")
             print(f"[*] Geo-location skipped for private IP: {source_ip}")

    # Ensure timestamp is a datetime object before logging
    # If timestamp is not provided by the honeypot, add current datetime for consistency.
    # If the honeypot provides a string timestamp, try to parse it to a datetime object.
    if "timestamp" not in event_details or event_details["timestamp"] is None:
         event_details["timestamp"] = datetime.utcnow() # Use UTC for consistency
         logging.debug(f"Added timestamp (utcnow): {event_details['timestamp']}")
    elif isinstance(event_details.get("timestamp"), str):
        try:
            # Attempt to parse common ISO formats or others if necessary
            # Example: "2023-10-27T10:00:00Z" or "2023-10-27T10:00:00+00:00"
            # datetime.fromisoformat handles 'Z' but requires it replaced for older Python versions
            event_details["timestamp"] = datetime.fromisoformat(event_details["timestamp"].replace('Z', '+00:00'))
            logging.debug(f"Parsed timestamp string to datetime: {event_details['timestamp']}")
        except ValueError:
             logging.warning(f"Could not parse timestamp string '{event_details['timestamp']}' to datetime. Keeping as string.")
             # If parsing fails, keep the string timestamp. Filtering by date range on this event might be impacted.


    if settings.DATABASE_ENABLED and db is not None:
        logging.info("Attempting database logging...")
        print("[*] Attempting database logging...")
        try:
            # Save event details as a document in the 'attacks' collection
            # Ensure event_details is a dictionary before insertion
            if not isinstance(event_details, dict):
                logging.error(f"Event details is not a dictionary: {type(event_details)}")
                print(f"[!] Event details is not a dictionary, cannot log to DB.")
                # Fallback to file logging if the data is not a dictionary
                logging.info(f"Event (fallback file log - not dict): {event_details}")
                return # Stop processing this event further in DB attempt

            result = db.attacks.insert_one(event_details)
            logging.info(f"Logged event to MongoDB: {result.inserted_id}")
            print(f"[*] Logged event to MongoDB: {result.inserted_id}")
            # Print a summary to console even when logging to DB
            summary = f"[*] DB Logged: {event_details.get('event_type', 'unknown event')} on port {event_details.get('destination_port', 'N/A')} from {source_ip}"
            if geolocation_data and geolocation_data.get("country") != "Private IP":
                summary += f" ({geolocation_data.get('city', 'N/A')}, {geolocation_data.get('country', 'N/A')})"
            elif geolocation_data and geolocation_data.get("country") == "Private IP":
                 summary += f" (Private IP)"
            print(summary)

        except OperationFailure as e:
             logging.error(f"MongoDB operation failed: {e}", exc_info=True)
             print(f"[!] MongoDB operation failed: {e}")
             print("[*] Falling back to file logging for this event due to DB operation failure.")
             # Log to file as a fallback
             logging.info(f"Event (fallback file log): {event_details}")
             print(f"[*] File Logged (DB Failed): {event_details.get('event_type', 'unknown event')} from {source_ip}")

        except Exception as e:
            logging.error(f"An unexpected error occurred during MongoDB logging: {e}", exc_info=True)
            print(f"[!] An unexpected error occurred during MongoDB logging: {e}")
            print("[*] Falling back to file logging for this event due to unexpected DB error.")
            # Log to file as a fallback
            logging.info(f"Event (fallback file log): {event_details}")
            print(f"[*] File Logged (DB Error): {event_details.get('event_type', 'unknown event')} from {source_ip}")


    else:
        logging.info("Database logging is not enabled or DB connection is None. Falling back to file logging.")
        print("[*] Database logging is not enabled or DB connection is None. Falling back to file logging.")
        # Fallback to file logging if database is not enabled or connection failed
        logging.info(f"Event (file log): {event_details}")
        summary = f"[*] File Logged: {event_details.get('event_type', 'unknown event')} on port {event_details.get('destination_port', 'N/A')} from {source_ip}"
        if geolocation_data and geolocation_data.get("country") != "Private IP":
            summary += f" ({geolocation_data.get('city', 'N/A')}, {geolocation_data.get('country', 'N/A')})"
        elif geolocation_data and geolocation_data.get("country") == "Private IP":
             summary += f" (Private IP)"
        print(summary)


# get_all_attack_events function remains the same - it uses the query_filter dictionary passed from app.py
def get_all_attack_events(query_filter=None):
    """Retrieves all attack events from the database, with optional filtering."""
    logging.debug(f"Database: get_all_attack_events called with query_filter={query_filter}.")
    print(f"[*] Database: get_all_attack_events called with query_filter={query_filter}.")

    if db is not None:
        try:
            # Use the provided query_filter or an empty dictionary if none is provided
            # The query_filter dictionary is built in web/app.py to include service, ip, port, date range, etc.
            cursor = db.attacks.find(query_filter if query_filter is not None else {})
            events_list = list(map(lambda event: {**event, '_id': str(event['_id'])}, cursor))
            logging.debug(f"Database: Query for get_all_attack_events found {len(events_list)} documents.")
            print(f"[*] Database: Query for get_all_attack_events found {len(events_list)} documents.")
            return events_list
        except Exception as e:
             logging.error(f"Database query error in get_all_attack_events: {e}", exc_info=True)
             print(f"[!] Database error during get_all_attack_events: {e}")
             return []

    logging.warning("Database: DB connection is None in get_all_attack_events.")
    print("[*] Database: DB connection is None in get_all_attack_events.")
    return []


# get_recent_attack_events function remains the same - it uses the query_filter dictionary passed from app.py
def get_recent_attack_events(limit=None, query_filter=None, sort_order=-1):
    """Retrieves the most recent attack events or events matching a filter from the database."""
    logging.debug(f"Database: get_recent_attack_events called with limit={limit}, query_filter={query_filter}, sort_order={sort_order}")
    print(f"[*] Database: get_recent_attack_events called with limit={limit}, query_filter={query_filter}, sort_order={sort_order}")


    if db is not None:
        try:
            # Start with the base find operation, using the provided query_filter
            # The query_filter dictionary is built in web/app.py to include _id, service, ip, port, date range, etc.
            cursor = db.attacks.find(query_filter if query_filter is not None else {})

            # Apply sorting
            if sort_order is not None:
                cursor = cursor.sort('_id', sort_order) # Sort by _id for recent/polling

            # Apply limit if specified (usually only on initial load when no since_id)
            if limit is not None:
                cursor = cursor.limit(limit)

            # Convert cursor to list and format _id
            events_list = list(map(lambda event: {**event, '_id': str(event['_id'])}, cursor))

            logging.debug(f"Database: Query for get_recent_attack_events found {len(events_list)} documents.")
            print(f"[*] Database: Query for get_recent_attack_events found {len(events_list)} documents.")
            return events_list

        except Exception as e:
             logging.error(f"Database query error in get_recent_attack_events: {e}", exc_info=True)
             print(f"[!] Database error during get_recent_attack_events: {e}")
             return [] # Return empty list on error

    logging.warning("Database: DB connection is None in get_recent_attack_events.")
    print("[*] Database: DB connection is None in get_recent_attack_events.")
    return []# data/database.py

import logging
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure
from config import settings
from core.geolocation import get_geolocation
import os
import sys
from bson.objectid import ObjectId # Import ObjectId for querying


# MongoDB client and database initialization
client = None
db = None

# Function to initialize logging
def init_logging():
    """Initializes logging to a file within the project's logs directory."""
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
    log_file_path = os.path.join(project_root, 'logs', 'honeypot.log')

    log_dir = os.path.dirname(log_file_path)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    logging.basicConfig(filename=log_file_path, level=logging.INFO, filemode='a',
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # Use root logger for initial setup messages
    logging.getLogger().info("Logging initialized.")


# Initialize MongoDB connection if database is enabled
if settings.DATABASE_ENABLED:
    try:
        # Ensure init_logging has been called before logging connection status
        # The check `if not logging.getLogger().handlers:` in app.py and run_honeypot.py
        # should handle this, but calling init_logging here ensures logger is ready
        if not logging.getLogger().handlers:
             init_logging()

        logging.info(f"Attempting to connect to MongoDB: {settings.DATABASE_URI}, Database: {settings.DATABASE_NAME}")
        print(f"[*] Attempting to connect to MongoDB: {settings.DATABASE_URI}, Database: {settings.DATABASE_NAME}")

        client = MongoClient(settings.DATABASE_URI, serverSelectionTimeoutMS=10000)
        client.admin.command('ismaster')
        db = client[settings.DATABASE_NAME]
        logging.info(f"Successfully connected to MongoDB: {settings.DATABASE_URI}, Database: {settings.DATABASE_NAME}")
        print(f"[*] Successfully connected to MongoDB: {settings.DATABASE_URI}, Database: {settings.DATABASE_NAME}")

    except ConnectionFailure as e:
        logging.error(f"Failed to connect to MongoDB at {settings.DATABASE_URI}: {e}")
        client = None # Ensure client is None if connection fails
        db = None
        logging.warning("Database logging is enabled but connection failed. Falling back to file logging.")
        print(f"[!] Failed to connect to MongoDB: {e}")

    except Exception as e:
         logging.error(f"An unexpected error occurred during MongoDB connection: {e}", exc_info=True) # Log traceback
         client = None
         db = None
         logging.warning("Database logging is enabled but an unexpected error occurred. Falling back to file logging.")
         print(f"[!] An unexpected error occurred during MongoDB connection: {e}")


def log_attack_event(event_details):
    """Logs a detected attack event to MongoDB or file, with optional geo-location."""
    # Use a dedicated logger or include the process/thread ID if running multi-process
    logging.info(f"log_attack_event called for event: {event_details.get('event_type', 'N/A')} from {event_details.get('source_ip', 'N/A')}")
    print(f"[*] log_attack_event called for event: {event_details.get('event_type', 'N/A')} from {event_details.get('source_ip', 'N/A')}")

    # Get geo-location if enabled and IP is available
    source_ip = event_details.get("source_ip")
    geolocation_data = None
    if source_ip:
        geolocation_data = get_geolocation(source_ip) # This function handles private IPs and API calls

    # Add geolocation data to event details if available
    if geolocation_data:
         event_details["geolocation"] = geolocation_data
         if geolocation_data.get("country") != "Private IP":
              logging.info(f"Geo-location added: {geolocation_data.get('city', 'N/A')}, {geolocation_data.get('country', 'N/A')}")
              print(f"[*] Geo-location added: {geolocation_data.get('city', 'N/A')}, {geolocation_data.get('country', 'N/A')}")
         else:
             logging.info(f"Geo-location skipped for private IP: {source_ip}")
             print(f"[*] Geo-location skipped for private IP: {source_ip}")


    if settings.DATABASE_ENABLED and db is not None:
        logging.info("Attempting database logging...")
        print("[*] Attempting database logging...")
        try:
            # Save event details as a document in the 'attacks' collection
            # Ensure event_details is a dictionary before insertion
            if not isinstance(event_details, dict):
                logging.error(f"Event details is not a dictionary: {type(event_details)}")
                print(f"[!] Event details is not a dictionary, cannot log to DB.")
                # Fallback to file logging if the data is not a dictionary
                logging.info(f"Event (fallback file log - not dict): {event_details}")
                return # Stop processing this event further in DB attempt

            result = db.attacks.insert_one(event_details)
            logging.info(f"Logged event to MongoDB: {result.inserted_id}")
            print(f"[*] Logged event to MongoDB: {result.inserted_id}")
            # Print a summary to console even when logging to DB
            summary = f"[*] DB Logged: {event_details.get('event_type', 'unknown event')} on port {event_details.get('destination_port', 'N/A')} from {source_ip}"
            if geolocation_data and geolocation_data.get("country") != "Private IP":
                summary += f" ({geolocation_data.get('city', 'N/A')}, {geolocation_data.get('country', 'N/A')})"
            elif geolocation_data and geolocation_data.get("country") == "Private IP":
                 summary += f" (Private IP)"
            print(summary)

        except OperationFailure as e:
             logging.error(f"MongoDB operation failed: {e}", exc_info=True)
             print(f"[!] MongoDB operation failed: {e}")
             print("[*] Falling back to file logging for this event due to DB operation failure.")
             # Log to file as a fallback
             logging.info(f"Event (fallback file log): {event_details}")
             print(f"[*] File Logged (DB Failed): {event_details.get('event_type', 'unknown event')} from {source_ip}")

        except Exception as e:
            logging.error(f"An unexpected error occurred during MongoDB logging: {e}", exc_info=True)
            print(f"[!] An unexpected error occurred during MongoDB logging: {e}")
            print("[*] Falling back to file logging for this event due to unexpected DB error.")
            # Log to file as a fallback
            logging.info(f"Event (fallback file log): {event_details}")
            print(f"[*] File Logged (DB Error): {event_details.get('event_type', 'unknown event')} from {source_ip}")


    else:
        logging.info("Database logging is not enabled or DB connection is None. Falling back to file logging.")
        print("[*] Database logging is not enabled or DB connection is None. Falling back to file logging.")
        # Fallback to file logging if database is not enabled or connection failed
        logging.info(f"Event (file log): {event_details}")
        summary = f"[*] File Logged: {event_details.get('event_type', 'unknown event')} on port {event_details.get('destination_port', 'N/A')} from {source_ip}"
        if geolocation_data and geolocation_data.get("country") != "Private IP":
            summary += f" ({geolocation_data.get('city', 'N/A')}, {geolocation_data.get('country', 'N/A')})"
        elif geolocation_data and geolocation_data.get("country") == "Private IP":
             summary += f" (Private IP)"
        print(summary)


# Modify get_all_attack_events to accept an optional query_filter
def get_all_attack_events(query_filter=None):
    """Retrieves all attack events from the database, with optional filtering."""
    logging.debug(f"Database: get_all_attack_events called with query_filter={query_filter}.")
    print(f"[*] Database: get_all_attack_events called with query_filter={query_filter}.")

    if db is not None:
        try:
            # Use the provided query_filter or an empty dictionary if none is provided
            # The query_filter dictionary is built in web/app.py to include service, ip, port, etc.
            cursor = db.attacks.find(query_filter if query_filter is not None else {})
            events_list = list(map(lambda event: {**event, '_id': str(event['_id'])}, cursor))
            logging.debug(f"Database: Query for get_all_attack_events found {len(events_list)} documents.")
            print(f"[*] Database: Query for get_all_attack_events found {len(events_list)} documents.")
            return events_list
        except Exception as e:
             logging.error(f"Database query error in get_all_attack_events: {e}", exc_info=True)
             print(f"[!] Database error during get_all_attack_events: {e}")
             return []

    logging.warning("Database: DB connection is None in get_all_attack_events.")
    print("[*] Database: DB connection is None in get_all_attack_events.")
    return []


# Modify get_recent_attack_events to accept query_filter and sort_order
def get_recent_attack_events(limit=None, query_filter=None, sort_order=-1):
    """Retrieves the most recent attack events or events matching a filter from the database."""
    logging.debug(f"Database: get_recent_attack_events called with limit={limit}, query_filter={query_filter}, sort_order={sort_order}")
    print(f"[*] Database: get_recent_attack_events called with limit={limit}, query_filter={query_filter}, sort_order={sort_order}")


    if db is not None:
        try:
            # Start with the base find operation, using the provided query_filter
            # The query_filter dictionary is built in web/app.py to include _id, service, ip, port, etc.
            cursor = db.attacks.find(query_filter if query_filter is not None else {})

            # Apply sorting
            if sort_order is not None:
                cursor = cursor.sort('_id', sort_order) # Sort by _id for recent/polling

            # Apply limit if specified (usually only on initial load when no since_id)
            if limit is not None:
                cursor = cursor.limit(limit)

            # Convert cursor to list and format _id
            events_list = list(map(lambda event: {**event, '_id': str(event['_id'])}, cursor))

            logging.debug(f"Database: Query for get_recent_attack_events found {len(events_list)} documents.")
            print(f"[*] Database: Query for get_recent_attack_events found {len(events_list)} documents.")
            return events_list

        except Exception as e:
             logging.error(f"Database query error in get_recent_attack_events: {e}", exc_info=True)
             print(f"[!] Database error during get_recent_attack_events: {e}")
             return [] # Return empty list on error

    logging.warning("Database: DB connection is None in get_recent_attack_events.")
    print("[*] Database: DB connection is None in get_recent_attack_events.")
    return []