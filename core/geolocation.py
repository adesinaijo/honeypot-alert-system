# core/geolocation.py

import requests
import logging
from config import settings

def get_geolocation(ip_address):
    """
    Gets geo-location information for an IP address using a public API.
    Returns a dictionary with location details or None if lookup fails.
    """
    if not settings.GEOLOCATION_ENABLED or not ip_address or ip_address == '127.0.0.1':
        # Don't perform lookups if disabled or for localhost
        return None

    # Avoid looking up private IP addresses
    if ip_address.startswith('10.') or \
       ip_address.startswith('172.16.') or (ip_address.startswith('172.') and 16 <= int(ip_address.split('.')[1]) <= 31) or \
       ip_address.startswith('192.168.'):
        logging.debug(f"Skipping geo-location for private IP: {ip_address}")
        return {"country": "Private IP", "city": "N/A"} # Return a placeholder

    api_url = f"{settings.GEOLOCATION_API_URL}{ip_address}"
    try:
        # Make the HTTP GET request to the API
        response = requests.get(api_url, timeout=5) # Set a timeout to prevent hanging
        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

        # Parse the JSON response
        geo_data = response.json()

        # ip-api.com returns a 'status' field. 'success' means a valid lookup.
        if geo_data.get("status") == "success":
            # Extract relevant information (adjust based on API response)
            location_info = {
                "country": geo_data.get("country"),
                "countryCode": geo_data.get("countryCode"),
                "region": geo_data.get("regionName"),
                "city": geo_data.get("city"),
                "zip": geo_data.get("zip"),
                "lat": geo_data.get("lat"),
                "lon": geo_data.get("lon"),
                "isp": geo_data.get("isp"),
                "org": geo_data.get("org"),
                "as": geo_data.get("as")
            }
            logging.debug(f"Geolocation for {ip_address}: {location_info}")
            return location_info
        else:
            logging.warning(f"Geolocation lookup failed for {ip_address}: {geo_data.get('message', 'Unknown error')}")
            return None

    except requests.exceptions.RequestException as e:
        # Handle network errors, timeouts, etc.
        logging.error(f"Geolocation API request failed for {ip_address}: {e}")
        return None
    except Exception as e:
        # Handle other potential errors
        logging.error(f"An unexpected error occurred during geolocation lookup for {ip_address}: {e}")
        return None

# You might need to install the 'requests' library: pip install requests