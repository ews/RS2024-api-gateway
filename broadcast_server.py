import socket
import threading
import json
import signal
import sys

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

        # Encode the string into bytes
        return clojure_data.encode('utf-8')

    except Exception as e:
        print(f"Error in transform_audio: {e}")
        return data



def transform_video(data):
    # TODO: Add transformation logic for 'video' data
    return data


import threading
import random
import requests  # Ensure the 'requests' library is installed

# Shared variables for keeping track of state
last_received_id = None
lights_lock = threading.Lock()  # Lock to ensure thread safety

def transform_lights(data, server_addresses):
    """
    Transform the input data and send HTTP requests to WLED servers
    to change the light pattern and color randomly whenever a new (different) ID is received.
    """
    global last_received_id

    try:
        # Parse the JSON input
        input_data = json.loads(data.decode('utf-8'))

        # Extract the 'id' field from the input data
        received_id = input_data.get('id')
        if received_id is None:
            print("No 'id' field found in the data.")
            return b''  # Return empty bytes as there's nothing to send

        if not server_addresses:
            print("No lights servers configured.")
            return b''

        # Use the lock to ensure thread safety when accessing shared variables
        with lights_lock:
            if received_id != last_received_id:
                # New ID received; change the pattern and color
                last_received_id = received_id

                # Randomly select an effect (pattern) ID
                max_effect_id = 117  # As of WLED version 0.13.0, adjust if needed
                effect_id = random.randint(0, max_effect_id)

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

                # Send the HTTP request to each WLED server
                for wled_address in server_addresses:
                    try:
                        WLED_IP, WLED_PORT = wled_address.split(':')
                        WLED_PORT = int(WLED_PORT)

                        # Prepare the request to the WLED server
                        url = f'http://{WLED_IP}:{WLED_PORT}/json/state'

                        # Send the HTTP POST request to the WLED server
                        response = requests.post(url, json=payload)

                        if response.status_code == 200:
                            print(f"Successfully changed WLED effect to {effect_id} with color RGB({color_r}, {color_g}, {color_b}) on {WLED_IP}:{WLED_PORT}")
                        else:
                            print(f"Failed to change WLED effect on {WLED_IP}:{WLED_PORT}. Status code: {response.status_code}")
                    except Exception as e:
                        print(f"Error sending request to WLED server {wled_address}: {e}")
            else:
                print(f"Received ID '{received_id}' is the same as the last one. No pattern change.")
                # No action needed as the ID is the same

        # Since we've handled the action, return empty bytes
        return b''

    except Exception as e:
        print(f"Error in transform_lights: {e}")
        return b''  # Return empty bytes on error



def _transform_lights(data, server_addresses):
    """
    Transform the input data and send HTTP requests to WLED servers
    to change the light pattern whenever a new (different) ID is received.
    """
    global last_received_id, current_pattern_index
    print("wled server ", server_addresses)

    try:
        # Parse the JSON input
        input_data = json.loads(data.decode('utf-8'))

        # Extract the 'id' field from the input data
        received_id = input_data.get('id')
        if received_id is None:
            print("No 'id' field found in the data.")
            return b''  # Return empty bytes as there's nothing to send

        if not server_addresses:
            print("No lights servers configured.")
            return b''

        # Use the lock to ensure thread safety when accessing shared variables
        with lights_lock:
            if received_id != last_received_id:
                # New ID received; change the pattern
                last_received_id = received_id

                # Update the pattern index to get the next pattern
                current_pattern_index = (current_pattern_index + 1) % len(pattern_list)
                pattern_number = pattern_list[current_pattern_index]

                # Prepare the parameters for the WLED API
                params = {
                    'PL': pattern_number  # Assuming 'PL' parameter selects a preset/pattern
                }

                # Send the HTTP request to each WLED server
                for wled_address in server_addresses:
                    try:
                        WLED_IP, WLED_PORT = wled_address.split(':')
                        WLED_PORT = int(WLED_PORT)

                        # Prepare the request to the WLED server
                        url = f'http://{WLED_IP}:{WLED_PORT}/win'

                        # Send the HTTP GET request to the WLED server
                        response = requests.get(url, params=params)

                        if response.status_code == 200:
                            print(f"Successfully changed WLED pattern to {pattern_number} on {WLED_IP}:{WLED_PORT}")
                        else:
                            print(f"Failed to change WLED pattern on {WLED_IP}:{WLED_PORT}. Status code: {response.status_code}")
                    except Exception as e:
                        print(f"Error sending request to WLED server {wled_address}: {e}")
            else:
                print(f"Received ID '{received_id}' is the same as the last one. No pattern change.")
                # No action needed as the ID is the same

        # Since we've handled the action, return empty bytes
        return b''

    except Exception as e:
        print(f"Error in transform_lights: {e}")
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
        print("No server addresses found. Exiting.")
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Set SO_REUSEADDR option to reuse the socket
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((LISTEN_HOST, LISTEN_PORT))
    server_socket.listen(5)
    print(f"Server listening on {LISTEN_HOST}:{LISTEN_PORT}")

    # Handle graceful shutdown on Ctrl+C
    def signal_handler(sig, frame):
        print("\nShutting down the server.")
        for client_socket in client_sockets:
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
                client_socket.close()
            except Exception as e:
                print(f"Error closing client socket: {e}")
        server_socket.close()
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
        print(f"Server error: {e}")
    finally:
        print("Closing server socket.")
        server_socket.close()

if __name__ == '__main__':
    start_server()
