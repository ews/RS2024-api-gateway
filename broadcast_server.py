import socket
import threading
import json
import signal
import sys

# Configuration
LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 9000
CONFIG_FILE = 'servers.json'
BUFFER_SIZE = 4096  # Increase buffer size to handle larger HTTP requests

# Keep track of client threads and sockets
client_threads = []
client_sockets = []

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

def parse_message(data, client_socket):
    """
    Parse the incoming data to extract the message type and content.
    """
    try:
        # Detect if data is an HTTP request
        if data.startswith(b'GET') or data.startswith(b'POST') or data.startswith(b'PUT') or data.startswith(b'DELETE'):
            # It's an HTTP request
            body = parse_http_request(data, client_socket)
            # For this example, assume the body contains JSON data
            msg_type = 'default'
            return msg_type, body
        else:
            # Try to parse as 'type|message'
            decoded_data = data.decode('utf-8', errors='ignore')
            if '|' in decoded_data:
                msg_type, msg_content = decoded_data.split('|', 1)
                msg_type = msg_type.strip().lower()
                return msg_type, msg_content.encode('utf-8')
            else:
                # No '|' found, assign default message type
                msg_type = 'default'
                return msg_type, data
    except Exception as e:
        print(f"Error parsing message: {e}")
        # Assign default message type
        return 'default', data

# Transformation functions for each type
def transform_audio(data):
    # TODO: Add transformation logic for 'audio' data
    return data

def transform_video(data):
    # TODO: Add transformation logic for 'video' data
    return data

def transform_lights(data):
    # TODO: Add transformation logic for 'lights' data
    return data

def transform_default(data):
    # No transformation for default data
    return data

# Mapping of message types to their corresponding transformation functions
TRANSFORM_FUNCTIONS = {
    'audio': transform_audio,
    'video': transform_video,
    'lights': transform_lights,
    'default': transform_default,
}

def handle_client_connection(client_socket, client_address, server_config):
    """Handle incoming client connections and broadcast data."""
    print(f"Connection from {client_address}")
    client_sockets.append(client_socket)  # Keep track of the client socket

    while True:
        try:
            data = client_socket.recv(BUFFER_SIZE)
            if not data:
                print(f"Connection closed by {client_address}")
                break

            # Log the received data
            print(f"Received data from {client_address}: {data}")

            # Parse the message to get the type and content
            msg_type, msg_content = parse_message(data, client_socket)

            # Log the message type and content
            print(f"Message type: {msg_type}, Content: {msg_content}")

            # Transform the data using the appropriate transformation function
            transform_func = TRANSFORM_FUNCTIONS.get(msg_type, lambda x: x)
            transformed_data = transform_func(msg_content)

            # Log the transformed data
            print(f"Transformed data for type '{msg_type}': {transformed_data}")

            # Get server addresses for the message type
            if msg_type in server_config:
                server_addresses = server_config[msg_type]
            else:
                # If unknown message type, broadcast to all servers
                print(f"Unknown message type '{msg_type}' from {client_address}, broadcasting to all servers.")
                server_addresses = []
                for addresses in server_config.values():
                    server_addresses.extend(addresses)

            # Broadcast transformed data to all servers
            for server_info in server_addresses:
                try:
                    server_host, server_port = server_info.split(':')
                    server_port = int(server_port)
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.connect((server_host, server_port))
                        s.sendall(transformed_data)
                        print(f"Sent transformed data to {server_host}:{server_port} for type '{msg_type}'")
                except Exception as e:
                    print(f"Error sending data to {server_info}: {e}")

        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
            break

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
