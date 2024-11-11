#!/bin/bash

# Configuration
URL="http://localhost:9000"  # Replace with your server's address and port if different
START=0
END=60
INTERVAL=1  # Interval in seconds

# Function to send POST request
send_post_request() {
  local id=$1
  curl -X POST -H "Content-Type: application/json" -d "{\"id\": \"$id\"}" "$URL"
}

# Iterate from START to END
for (( i=START; i<=END; i++ ))
do
  send_post_request "$i"
  echo "Sent id: $i"
  sleep "$INTERVAL"
done

echo "All IDs sent successfully."

