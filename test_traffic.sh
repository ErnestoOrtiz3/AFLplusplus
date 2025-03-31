#!/bin/bash
# Script to generate test traffic to AFL ports

# Default ports to test
AFL_PORTS="8080 9000"
NON_AFL_PORTS="8081 9001"
HOST="127.0.0.1"

# Function to send TCP traffic to a port
send_tcp_traffic() {
    local port=$1
    echo "Sending TCP traffic to $HOST:$port..."
    # Try to connect to the port (will fail, but generates packets)
    timeout 1 nc -zv $HOST $port 2>&1 || true
    # Alternative using curl
    timeout 1 curl -s $HOST:$port > /dev/null 2>&1 || true
}

echo "Generating traffic to AFL ports..."
for port in $AFL_PORTS; do
    send_tcp_traffic $port
done

echo "Generating traffic to non-AFL ports..."
for port in $NON_AFL_PORTS; do
    send_tcp_traffic $port
done

# Also send some ICMP traffic (ping)
echo "Sending ICMP traffic..."
ping -c 5 $HOST > /dev/null

echo "Traffic generation complete."