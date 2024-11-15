import threading
import json
import signal
import sys
import requests  # Ensure 'requests' is imported
import random
import socket
import logging
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configuration
LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 9000
CONFIG_FILE = "servers.json"
BUFFER_SIZE = 4096  # Adjust buffer size as needed

# Healthcheck Ping URL
HEALTHCHECK_URL = "https://hc-ping.com/364f22b0-20c9-4cbc-ba77-b35bd4efb164"

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)

# Initialize a thread pool for asynchronous HTTP requests
executor = ThreadPoolExecutor(max_workers=10)

# Shared variables for keeping track of WLED lights state
last_received_id = None
current_combination_index = 0
effect_list = []  # To be populated with available effect IDs
combination_list = []  # List of 60 color-effect combinations
lights_lock = threading.Lock()  # Lock to ensure thread safety

# Keep track of client threads and sockets
client_threads = []
client_sockets = []


def send_wled_request(wled_address, payload):
    """
    Send an HTTP POST request to the WLED server with retry logic.
    """
    try:
        WLED_IP, WLED_PORT = wled_address.split(":")
        WLED_PORT = int(WLED_PORT)
        url = f"http://{WLED_IP}:{WLED_PORT}/json/state"

        # Setup retry strategy
        retries = Retry(
            total=3,  # Total number of retries
            backoff_factor=1,  # Wait 1s, then 2s, then 4s between retries
            status_forcelist=[502, 503, 504],  # Retry on these HTTP status codes
            allowed_methods=["POST"],  # Only retry POST requests
        )
        adapter = HTTPAdapter(max_retries=retries)
        session = requests.Session()
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        response = session.post(url, json=payload, timeout=5)  # 5-second timeout
        response.raise_for_status()

        logging.info(
            f"Successfully changed WLED effect to {payload['seg'][0]['fx']} with color RGB({payload['seg'][0]['col'][0][0]}, {payload['seg'][0]['col'][0][1]}, {payload['seg'][0]['col'][0][2]}) on {WLED_IP}:{WLED_PORT}"
        )
    except requests.exceptions.Timeout:
        logging.error(f"Timeout while sending request to WLED server {wled_address}")
    except requests.exceptions.ConnectionError:
        logging.error(
            f"Connection error while sending request to WLED server {wled_address}"
        )
    except requests.exceptions.HTTPError as http_err:
        logging.error(
            f"HTTP error while sending request to WLED server {wled_address}: {http_err}"
        )
    except Exception as e:
        logging.error(
            f"Unexpected error sending request to WLED server {wled_address}: {e}"
        )


def load_server_addresses(config_file):
    """Load server addresses from the JSON configuration file."""
    try:
        with open(config_file, "r") as f:
            config = json.load(f)
        return config
    except Exception as e:
        logging.error(f"Error reading config file: {e}")
        return {}


def parse_http_request(data, client_socket):
    """
    Parse an HTTP request and extract the message body.
    """
    try:
        decoded_data = data.decode("utf-8", errors="ignore")
        headers, _, body = decoded_data.partition("\r\n\r\n")
        header_lines = headers.split("\r\n")
        first_line = header_lines[0]
        method, path, http_version = first_line.split()
        # Extract Content-Length
        content_length = 0
        for line in header_lines[1:]:
            if line.lower().startswith("content-length:"):
                content_length = int(line.split(":", 1)[1].strip())
                break
        # Read the remaining data if necessary
        body_bytes = body.encode("utf-8")
        while len(body_bytes) < content_length:
            more_data = client_socket.recv(BUFFER_SIZE)
            if not more_data:
                break
            body_bytes += more_data
        return body_bytes
    except Exception as e:
        logging.error(f"Error parsing HTTP request: {e}")
        return data


# Transformation functions for each type
def transform_music(data):
    try:
        # Parse the JSON input
        input_data = json.loads(data.decode("utf-8"))

        # Define role to event mapping
        role_event_mapping = {
            "music": ":location",
            "pause": ":pause",
            "SeekTo": ":seek-to",
            # TODO: add more events as needed
        }

        # Extract role and map to event
        role = input_data.get("role")
        event_name = role_event_mapping.get(role, ":location")

        # Handle arguments
        event_args = []
        if "id" in input_data:
            event_args.append(f"{input_data['id']}")
        if "position" in input_data:
            event_args.append(str(input_data["position"]))
        # Add more argument handling as needed

        # Construct the Clojure data structure
        args_str = " ".join(event_args)
        if args_str:
            clojure_data = f"[{event_name} {args_str}]"
        else:
            clojure_data = f"[{event_name}]"
        logging.info(f"Sending this to Neils event: {clojure_data.encode('utf-8')}")

        # Encode the string into bytes
        return clojure_data.encode("utf-8")

    except Exception as e:
        logging.error(f"Error in transform_music: {e}")
        return data


def transform_video(data):
    """
    Transform the input data and send an HTTP POST request to the video servers
    using the 'requests' library with proper headers and payload.
    """
    try:
        # Parse the JSON input
        input_data = json.loads(data.decode('utf-8'))

        endpoint = ""
        headers = {
            "Content-Type": "application/json"
        }

        # Construct the full URL for each video server
        for server_info in server_addresses:
            try:
                url = f"http://192.168.0.212:8002"  #FUCK IT!!!!

                # Send the POST request using 'requests'
                response = requests.post(url, headers=headers, json=input_data, timeout=5)

                # Raise an exception for bad status codes
                response.raise_for_status()

                logging.info(f"Successfully sent data to video server {server_host}:{server_port}. Response: {response.status_code}")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error sending data to video server {server_info}: {e}")

        # Since the action is complete, return an empty byte string
        return b''

    except json.JSONDecodeError:
        logging.error(f"Invalid JSON received for video server: {data}")
        return b''
    except Exception as e:
        logging.error(f"Error in transform_video: {e}")
        return b''



def fetch_available_effects(server_addresses):
    """
    Fetch available effects from the first WLED server in the list.
    Populate the global effect_list with effect IDs.
    Also, generate the combination_list with 60 color-effect combinations.
    """
    global effect_list
    global combination_list
    global current_combination_index

    if not server_addresses:
        logging.error("No lights servers configured.")
        return

    # Use the first server to fetch available effects
    wled_address = server_addresses[0]
    try:
        WLED_IP, WLED_PORT = wled_address.split(":")
        WLED_PORT = int(WLED_PORT)
        url = f"http://{WLED_IP}:{WLED_PORT}/json/effects"
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
        if isinstance(effects_json, list) and all(
            isinstance(item, str) for item in effects_json
        ):
            effects = effects_json
            # Assign IDs based on list indices (0-based)
            effect_list = list(range(len(effects)))
            logging.info(
                f"Fetched {len(effect_list)} effects from WLED server {WLED_IP}:{WLED_PORT}"
            )
        # Handle response if it's a list of dicts with 'id' and 'name'
        elif isinstance(effects_json, list) and all(
            isinstance(item, dict) and "id" in item for item in effects_json
        ):
            effects = effects_json
            effect_list = [item["id"] for item in effects]
            logging.info(
                f"Fetched {len(effect_list)} effects from WLED server {WLED_IP}:{WLED_PORT}"
            )
        # Handle response if it's a dict with 'effects' key containing a list
        elif (
            isinstance(effects_json, dict)
            and "effects" in effects_json
            and isinstance(effects_json["effects"], list)
        ):
            effects = effects_json["effects"]
            effect_list = [effect["id"] for effect in effects if "id" in effect]
            logging.info(
                f"Fetched {len(effect_list)} effects from WLED server {WLED_IP}:{WLED_PORT}"
            )
        else:
            logging.error(
                f"Unexpected effects JSON structure from {wled_address}: {effects_json}"
            )
            return

        # After fetching effects, generate the combination_list
        if len(effect_list) < 60:
            logging.warning(
                f"Effect list has {len(effect_list)} effects, which is less than 60. Some effects will be reused."
            )

        # Define 30 harmonious predefined colors
        predefined_colors = [
            (255, 0, 0),  # Red
            (0, 255, 0),  # Green
            (0, 0, 255),  # Blue
            (255, 255, 0),  # Yellow
            (255, 0, 255),  # Magenta
            (0, 255, 255),  # Cyan
            (192, 192, 192),  # Silver
            (128, 0, 0),  # Maroon
            (128, 128, 0),  # Olive
            (0, 128, 0),  # Dark Green
            (128, 0, 128),  # Purple
            (0, 128, 128),  # Teal
            (0, 0, 128),  # Navy
            (255, 165, 0),  # Orange
            (255, 192, 203),  # Pink
            (128, 0, 255),  # Indigo
            (75, 0, 130),  # Indigo
            (173, 255, 47),  # Green Yellow
            (34, 139, 34),  # Forest Green
            (255, 20, 147),  # Deep Pink
            (255, 69, 0),  # Orange Red
            (0, 100, 0),  # Dark Green
            (255, 215, 0),  # Gold
            (0, 255, 127),  # Spring Green
            (255, 105, 180),  # Hot Pink
            (139, 69, 19),  # Saddle Brown
            (240, 230, 140),  # Khaki
            (154, 205, 50),  # Yellow Green
            (255, 127, 80),  # Coral
            (0, 191, 255),  # Deep Sky Blue
            (34, 139, 34),  # Forest Green
        ]

        # Generate additional predefined colors to reach 30 if necessary
        while len(predefined_colors) < 30:
            predefined_colors.append(
                (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
            )

        # Generate 30 random colors
        random_colors = [
            (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
            for _ in range(30)
        ]

        # Combine predefined and random colors
        combined_colors = predefined_colors[:30] + random_colors[:30]

        # Shuffle to mix predefined and random colors
        random.shuffle(combined_colors)

        # Ensure we have exactly 60 colors
        if len(combined_colors) < 60:
            # Pad with random colors if needed
            combined_colors += [
                (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
                for _ in range(60 - len(combined_colors))
            ]

        # Generate 60 combinations
        combination_list = []
        for i in range(60):
            fx = effect_list[i % len(effect_list)]
            color = combined_colors[i]
            combination_list.append({"fx": fx, "color": color})

        # Reset the current combination index
        current_combination_index = 0

        logging.info("Generated 60 color-effect combinations.")

    except json.JSONDecodeError:
        logging.error(f"Invalid JSON received: {data}")
        return b""  # Return empty bytes on error
    except Exception as e:
        logging.error(f"Error in transform_lights: {e}")
        return b""  # Return empty bytes on error


def transform_lights(data, server_addresses):
    """
    Transform the input data and send HTTP requests to WLED servers
    to change the light pattern and color based on 60 unique combinations.
    """
    global last_received_id, current_combination_index, combination_list

    try:
        # Parse the JSON input
        input_data = json.loads(data.decode("utf-8"))

        # Extract the 'id' field from the input data
        received_id = input_data.get("id")
        if received_id is None:
            logging.warning("No 'id' field found in the data.")
            return b""  # Return empty bytes as there's nothing to send

        if not server_addresses:
            logging.warning("No lights servers configured.")
            return b""

        # Use the lock to ensure thread safety when accessing shared variables
        with lights_lock:
            if received_id != last_received_id:
                # New ID received; change the effect and color
                last_received_id = received_id

                # Select the next combination
                combination = combination_list[current_combination_index]
                fx = combination["fx"]
                color = combination["color"]

                # Update the combination index
                current_combination_index = (current_combination_index + 1) % len(
                    combination_list
                )

                # Prepare the JSON payload for the WLED API
                payload = {
                    "on": True,
                    "bri": 255,  # Maximum brightness
                    "seg": [
                        {
                            "id": 0,
                            "fx": fx,
                            "sx": random.randint(0, 255),  # Effect speed
                            "ix": random.randint(0, 255),  # Effect intensity
                            "col": [
                                [color[0], color[1], color[2]],  # Primary color
                                [0, 0, 0],  # Secondary color
                                [0, 0, 0],  # Tertiary color
                            ],
                        }
                    ],
                }

                # Log the selected effect and color
                logging.info(
                    f"Selected Effect ID: {fx}, Color RGB({color[0]}, {color[1]}, {color[2]})"
                )

                # Submit tasks to the thread pool for asynchronous execution
                for wled_address in server_addresses:
                    executor.submit(send_wled_request, wled_address, payload)
            else:
                logging.info(
                    f"Received ID '{received_id}' is the same as the last one. No pattern change."
                )
                # No action needed as the ID is the same

        # Since we've handled the action, return empty bytes
        return b""

    except json.JSONDecodeError:
        logging.error(f"Invalid JSON received: {data}")
        return b""  # Return empty bytes on error
    except Exception as e:
        logging.error(f"Error in transform_lights: {e}")
        return b""  # Return empty bytes on error


# Mapping of transformation functions for each server type
TRANSFORM_FUNCTIONS = {
    "music": transform_music,
    "video": transform_video,
    "lights": transform_lights,
}


def handle_client_connection(client_socket, client_address, server_config):
    """Handle incoming client connections and broadcast data."""
    logging.info(f"Connection from {client_address}")
    client_sockets.append(client_socket)  # Keep track of the client socket

    try:
        data = client_socket.recv(BUFFER_SIZE)
        if not data:
            logging.info(f"Connection closed by {client_address}")
            return

        # Log the received data
        logging.info(f"Received data from {client_address}: {data}")

        # Send a request to the health check URL
        # try:
        #     hc_response = requests.get(HEALTHCHECK_URL, timeout=5)
        #     if hc_response.status_code == 200:
        #         logging.info("Successfully pinged health check URL.")
        #     else:
        #         logging.error(f"Health check URL responded with status code {hc_response.status_code}")
        # except Exception as e:
        #     logging.error(f"Error sending health check ping: {e}")

        # Check if the data is an HTTP request
        if (
            data.startswith(b"GET")
            or data.startswith(b"POST")
            or data.startswith(b"PUT")
            or data.startswith(b"DELETE")
        ):
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
                # Transform the data using the appropriate function
                if server_type == "lights":
                    transformed_data = transform_func(message_content, server_addresses)
                else:
                    transformed_data = transform_func(message_content)
                # Log the transformed data
                logging.info(
                    f"Transformed data for type '{server_type}': {transformed_data}"
                )

                # If the transformed data is empty, skip sending
                if not transformed_data:
                    continue

                # Send transformed data to all servers of this type
                for server_info in server_addresses:
                    try:
                        server_host, server_port = server_info.split(":")
                        server_port = int(server_port)
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                            s.connect((server_host, server_port))
                            s.sendall(transformed_data)
                            logging.info(
                                f"Sent transformed data to {server_host}:{server_port} for type '{server_type}'"
                            )
                    except Exception as e:
                        logging.error(f"Error sending data to {server_info}: {e}")
            except Exception as e:
                logging.error(
                    f"Error processing data for server type '{server_type}': {e}"
                )

    except Exception as e:
        logging.error(f"Error handling client {client_address}: {e}")
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
    fetch_available_effects(server_config.get("lights", []))
    if not effect_list:
        logging.error("No effects fetched. Exiting.")
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Set SO_REUSEADDR option to reuse the socket
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((LISTEN_HOST, LISTEN_PORT))
    except Exception as e:
        logging.error(f"Failed to bind to {LISTEN_HOST}:{LISTEN_PORT}: {e}")
        sys.exit(1)

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
                args=(client_sock, client_addr, server_config),
            )
            client_handler.start()
            client_threads.append(client_handler)
    except Exception as e:
        logging.error(f"Server error: {e}")
    finally:
        logging.info("Closing server socket.")
        server_socket.close()


if __name__ == "__main__":
    start_server()
