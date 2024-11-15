import threading
import json
import signal
import sys
import requests  # Ensure 'requests' is imported
import random
import threading
import socket
import logging

# Configuration
LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 9000
CONFIG_FILE = 'servers.json'
BUFFER_SIZE = 4096  # Adjust buffer size as needed

# Keep track of client threads and sockets
client_threads = []
client_sockets = []

# Shared variables for keeping track of WLED lights state
last_received_id = None
current_pattern_index = 0
pattern_list = [0, 1, 2, 3, 4, 5]  # Define the list of patterns you want to cycle through
lights_lock = threading.Lock()  # Lock to ensure thread safety
#
## Healthcheck Ping URL
HEALTHCHECK_URL = 'https://hc-ping.com/364f22b0-20c9-4cbc-ba77-b35bd4efb164'


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')


def send_wled_request(wled_address, payload):
    """
    Send an HTTP POST request to the WLED server with retry logic.
    """
    try:
        WLED_IP, WLED_PORT = wled_address.split(':')
        WLED_PORT = int(WLED_PORT)
        url = f'http://{WLED_IP}:{WLED_PORT}/json/state'

        # Setup retry strategy
        retries = Retry(
            total=3,  # Total number of retries
            backoff_factor=1,  # Wait 1s, then 2s, then 4s between retries
            status_forcelist=[502, 503, 504],  # Retry on these HTTP status codes
            allowed_methods=["POST"]  # Only retry POST requests
        )
        adapter = HTTPAdapter(max_retries=retries)
        session = requests.Session()
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        response = session.post(url, json=payload, timeout=5)  # 5-second timeout
        response.raise_for_status()

        logging.info(
            f"Successfully changed WLED effect to {payload['seg'][0]['fx']} with color RGB({payload['seg'][0]['col'][0][0]}, {payload['seg'][0]['col'][0][1]}, {payload['seg'][0]['col'][0][2]}) on {WLED_IP}:{WLED_PORT}"
        )
    except requests.exceptions.Timeout:
        logging.error(f"Timeout while sending request to WLED server {wled_address}")
    except requests.exceptions.ConnectionError:
        logging.error(f"Connection error while sending request to WLED server {wled_address}")
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error while sending request to WLED server {wled_address}: {http_err}")
    except Exception as e:
        logging.error(f"Unexpected error sending request to WLED server {wled_address}: {e}")


def load_server_addresses(config_file):
    """Load server addresses from the JSON configuration file."""
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        return config
    except Exception as e:
        print(f"Error reading config file: {e}")
        return {}

def parse_http_request(data, client_socket):
    """
    Parse an HTTP request and extract the message body.
    """
    try:
        decoded_data = data.decode('utf-8', errors='ignore')
        headers, _, body = decoded_data.partition('\r\n\r\n')
        header_lines = headers.split('\r\n')
        first_line = header_lines[0]
        method, path, http_version = first_line.split()
        # Extract Content-Length
        content_length = 0
        for line in header_lines[1:]:
            if line.lower().startswith('content-length:'):
                content_length = int(line.split(':', 1)[1].strip())
                break
        # Read the remaining data if necessary
        body_bytes = body.encode('utf-8')
        while len(body_bytes) < content_length:
            more_data = client_socket.recv(BUFFER_SIZE)
            if not more_data:
                break
            body_bytes += more_data
        return body_bytes
    except Exception as e:
        print(f"Error parsing HTTP request: {e}")
        return data

# Transformation functions for each type
def transform_audio(data):
    try:
        # Parse the JSON input
        input_data = json.loads(data.decode('utf-8'))

        # Define role to event mapping
        role_event_mapping = {
            "music": ":play",
            "pause": ":pause",
            "SeekTo": ":seek-to",
            #TODO add more events I guess ? @neilyio
        }

        # Extract role and map to event
        role = input_data.get("role")
        event_name = role_event_mapping.get(role, ":unknown-event")

        # Handle arguments
        event_args = []
        if "id" in input_data:
            event_args.append(f":{input_data['id']}")
        if "position" in input_data:
            event_args.append(str(input_data["position"]))
        # Add more argument handling as needed

        # Construct the Clojure data structure
        args_str = ' '.join(event_args)
        if args_str:
            clojure_data = f'[{event_name} {args_str}]'
        else:
            clojure_data = f'[{event_name}]'
        print("sending this to Neils event", clojure_data.encode('utf-8'))

        # Encode the string into bytes
        return clojure_data.encode('utf-8')

    except Exception as e:
        print(f"Error in transform_audio: {e}")
        return data


## TODO nothing happens here I think ? FIXME @pablo
def transform_video(data):
    # TODO: Add transformation logic for 'video' data
    return data


# Shared variables for keeping track of state for WLED shit
last_received_id = None
current_effect_index = 0
effect_list = []  # To be populated with available effect IDs
lights_lock = threading.Lock()  # Lock to ensure thread safety



def fetch_available_effects(server_addresses):
    """
    Fetch available effects from the first WLED server in the list.
    Populate the global effect_list with effect IDs.
    """
    global effect_list
    if not server_addresses:
        logging.error("No lights servers configured.")
        return

    # Use the first server to fetch available effects
    wled_address = server_addresses[0]
    try:
        WLED_IP, WLED_PORT = wled_address.split(':')
        WLED_PORT = int(WLED_PORT)
        url = f'http://{WLED_IP}:{WLED_PORT}/json/effects'
        response = requests.get(url, timeout=5)
        response.raise_for_status()

        try:
            effects_json = response.json()
            logging.debug(f"Effects JSON: {effects_json}")
            logging.debug(f"Type of effects_json: {type(effects_json)}")
        except ValueError:
            logging.error(f"Non-JSON response from {wled_address}: {response.text}")
            return

        # Handle response if it's a list of strings
        if isinstance(effects_json, list) and all(isinstance(item, str) for item in effects_json):
            effects = effects_json
            # Assign IDs based on list indices (0-based)
            effect_list = list(range(len(effects)))
            logging.info(f"Fetched {len(effect_list)} effects from WLED server {WLED_IP}:{WLED_PORT}")
        # Handle response if it's a list of dicts with 'id' and 'name'
        elif isinstance(effects_json, list) and all(isinstance(item, dict) and 'id' in item for item in effects_json):
            effects = effects_json
            effect_list = [item['id'] for item in effects]
            logging.info(f"Fetched {len(effect_list)} effects from WLED server {WLED_IP}:{WLED_PORT}")
        # Handle response if it's a dict with 'effects' key containing a list
        elif isinstance(effects_json, dict) and 'effects' in effects_json and isinstance(effects_json['effects'], list):
            effects = effects_json['effects']
            effect_list = [effect['id'] for effect in effects if 'id' in effect]
            logging.info(f"Fetched {len(effect_list)} effects from WLED server {WLED_IP}:{WLED_PORT}")
        else:
            logging.error(f"Unexpected effects JSON structure from {wled_address}: {effects_json}")
            return

    except Exception as e:
        logging.error(f"Error fetching effects from WLED server {wled_address}: {e}")

def transform_lights(data, server_addresses):
    """
    Transform the input data and send HTTP requests to WLED servers
    to change the light pattern and color randomly or sequentially
    whenever a new (different) ID is received.
    """
    global last_received_id, current_effect_index, effect_list

    try:
        # Parse the JSON input
        input_data = json.loads(data.decode('utf-8'))

        # Extract the 'id' field from the input data
        received_id = input_data.get('id')
        if received_id is None:
            logging.warning("No 'id' field found in the data.")
            return b''  # Return empty bytes as there's nothing to send

        if not server_addresses:
            logging.warning("No lights servers configured.")
            return b''

        # Initialize effect list if empty
        with lights_lock:
            if not effect_list:
                fetch_available_effects(server_addresses)
                if not effect_list:
                    logging.error("No effects available. Cannot change WLED patterns.")
                    return b''

        # Use the lock to ensure thread safety when accessing shared variables
        with lights_lock:
            if received_id != last_received_id:
                # New ID received; change the effect and color
                last_received_id = received_id

                # Select the next effect (cycling through the list)
                effect_id = effect_list[current_effect_index]
                current_effect_index = (current_effect_index + 1) % len(effect_list)

                # Alternatively, to select a random effect, uncomment the following line:
                # effect_id = random.choice(effect_list)

                # Randomly generate RGB values (0-255)
                color_r = random.randint(0, 255)
                color_g = random.randint(0, 255)
                color_b = random.randint(0, 255)

                # Prepare the JSON payload for the WLED API
                payload = {
                    "on": True,
                    "bri": 255,  # Maximum brightness
                    "seg": [{
                        "id": 0,
                        "fx": effect_id,
                        "sx": random.randint(0, 255),  # Effect speed
                        "ix": random.randint(0, 255),  # Effect intensity
                        "col": [
                            [color_r, color_g, color_b],  # Primary color
                            [0, 0, 0],                    # Secondary color
                            [0, 0, 0]                     # Tertiary color
                        ]
                    }]
                }

                # Log the selected effect and color
                logging.info(f"Selected Effect ID: {effect_id}, Color RGB({color_r}, {color_g}, {color_b})")

                # Submit tasks to the thread pool for asynchronous execution
                for wled_address in server_addresses:
                    executor.submit(send_wled_request, wled_address, payload)
            else:
                logging.info(f"Received ID '{received_id}' is the same as the last one. No pattern change.")
                # No action needed as the ID is the same

        # Since we've handled the action, return empty bytes
        return b''

    except json.JSONDecodeError:
        logging.error(f"Invalid JSON received: {data}")
        return b''  # Return empty bytes on error
    except Exception as e:
        logging.error(f"Error in transform_lights: {e}")
        return b''  # Return empty bytes on error


# Mapping of transformation functions for each server type
TRANSFORM_FUNCTIONS = {
    'audio': transform_audio,
    'video': transform_video,
    'lights': transform_lights,
}

def handle_client_connection(client_socket, client_address, server_config):
    """Handle incoming client connections and broadcast data."""
    print(f"Connection from {client_address}")
    client_sockets.append(client_socket)  # Keep track of the client socket

    try:
        data = client_socket.recv(BUFFER_SIZE)
        if not data:
            print(f"Connection closed by {client_address}")
            return

        # Log the received data
        print(f"Received data from {client_address}: {data}")

        # Send a request to the health check URL
        try:
            hc_response = requests.get(HEALTHCHECK_URL)
            if hc_response.status_code == 200:
                print("Successfully pinged health check URL.")
            else:
                print(f"Health check URL responded with status code {hc_response.status_code}")
        except Exception as e:
            print(f"Error sending health check ping: {e}")

        # Check if the data is an HTTP request
        if data.startswith(b'GET') or data.startswith(b'POST') or data.startswith(b'PUT') or data.startswith(b'DELETE'):
            # Parse the HTTP request to get the body
            body = parse_http_request(data, client_socket)
            message_content = body
        else:
            # If not HTTP, use the raw data
            message_content = data

        # For each server type, transform and send the data
        for server_type, transform_func in TRANSFORM_FUNCTIONS.items():
            try:

                server_addresses = server_config.get(server_type, [])
                if server_type == 'lights':
                    transformed_data = transform_func(message_content, server_addresses)
                else:
                    transformed_data = transform_func(message_content)
                # Log the transformed data
                print(f"Transformed data for type '{server_type}': {transformed_data}")

                # Send transformed data to all servers of this type
                for server_info in server_addresses:
                    try:
                        server_host, server_port = server_info.split(':')
                        server_port = int(server_port)
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.connect((server_host, server_port))
                            s.sendall(transformed_data)
                            print(f"Sent transformed data to {server_host}:{server_port} for type '{server_type}'")
                    except Exception as e:
                        print(f"Error sending data to {server_info}: {e}")
            except Exception as e:
                print(f"Error processing data for server type '{server_type}': {e}")

    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        client_socket.close()
        client_sockets.remove(client_socket)  # Remove from the list when done

def start_server():
    """Start the socket server and listen for connections."""
    server_config = load_server_addresses(CONFIG_FILE)
    if not server_config:
        logging.error("No server addresses found. Exiting.")
        return

    # Fetch effects for 'lights' before starting
    fetch_available_effects(server_config.get('lights', []))
    if not effect_list:
        logging.error("No effects fetched. Exiting.")
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Set SO_REUSEADDR option to reuse the socket
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((LISTEN_HOST, LISTEN_PORT))
    server_socket.listen(5)
    logging.info(f"Server listening on {LISTEN_HOST}:{LISTEN_PORT}")

    # Handle graceful shutdown on Ctrl+C
    def signal_handler(sig, frame):
        logging.info("\nShutting down the server.")
        for client_socket in client_sockets:
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
                client_socket.close()
            except Exception as e:
                logging.error(f"Error closing client socket: {e}")
        server_socket.close()
        executor.shutdown(wait=False)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        while True:
            client_sock, client_addr = server_socket.accept()
            client_handler = threading.Thread(
                target=handle_client_connection,
                args=(client_sock, client_addr, server_config)
            )
            client_handler.start()
            client_threads.append(client_handler)
    except Exception as e:
        logging.error(f"Server error: {e}")
    finally:
        logging.info("Closing server socket.")
        server_socket.close()



if __name__ == '__main__':
    start_server()
