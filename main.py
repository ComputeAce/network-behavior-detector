import socket
import struct
import time
import threading
from flask import Flask, Response, jsonify, send_from_directory
from flask_cors import CORS
import base64
import queue

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Queues to hold data
data_queue = queue.Queue()
processed_data_queue = queue.Queue()

# A list to hold the packet data for exposing over HTTP
exposed_data = []

# Serve static files (e.g., HTML, JS) from the 'static' folder
@app.route('/static/<path:filename>')
def serve_static_file(filename):
    return send_from_directory('static', filename)

# Endpoint to retrieve the exposed data
@app.route('/data', methods=['GET'])
def get_exposed_data():
    return jsonify(exposed_data)

# SSE (Server-Sent Events) endpoint to stream real-time packet data
@app.route('/stream', methods=['GET'])
def stream_data():
    def generate():
        while True:
            if exposed_data:
                data = exposed_data[-1]
                yield f"data: {data}\n\n"
                time.sleep(1)

    return Response(generate(), content_type='text/event-stream')

def main():
    try:
        # Create the raw socket to listen to network packets
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind(("0.0.0.0", 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        conn.settimeout(10)  # Timeout after 10 seconds for socket
        print("Listening for packets...")

        # Start a separate thread to expose processed data
        expose_thread = threading.Thread(target=expose_data)
        expose_thread.daemon = True
        expose_thread.start()

        # Start Flask in a separate thread
        flask_thread = threading.Thread(target=run_flask)
        flask_thread.daemon = True
        flask_thread.start()

        while True:
            try:
                raw_data, addr = conn.recvfrom(65535)  # Capture raw data packets
                print(f"\nPacket received from {addr}:")
                process_packet(raw_data)  # Process and print packet details

                # Push processed packet data into the queue to be exposed
                processed_data_queue.put(raw_data)

                # Check if there is data to expose (from the processing queue)
                if not data_queue.empty():
                    data_queue.put(processed_data_queue.get())

            except socket.timeout:
                print("No packets received within the timeout period. Continuing to listen...")

            except Exception as e:
                print(f"Error during packet capture: {e}")
                continue  # Continue capturing packets even if an error occurs

    except PermissionError:
        print("Permission denied: Run the script with Administrator privileges.")
    except OSError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\nExiting...")  # Graceful exit on Ctrl+C
        exit(0)

def process_packet(raw_data):
    try:
        version, header_length, ttl, proto, src, target, data = ipv4_packet(raw_data)
        print(f"Packet from {src} to {target} with protocol {proto}")
        
        # Handle different protocols based on the 'proto' field
        if proto == 6:  # TCP
            tcp_header = tcp_segment(data)
            print(f"TCP Source Port: {tcp_header['src_port']} Destination Port: {tcp_header['dest_port']}")
            print(f"Sequence: {tcp_header['seq']} Ack: {tcp_header['ack']}")
            print(f"Data: {tcp_header['data']}")
        elif proto == 17:  # UDP
            udp_header = udp_segment(data)
            print(f"UDP Source Port: {udp_header['src_port']} Destination Port: {udp_header['dest_port']}")
            print(f"Data: {udp_header['data']}")
        elif proto == 1:  # ICMP
            icmp_header = icmp_packet(data)
            print(f"ICMP Type: {icmp_header['type']} Code: {icmp_header['code']}")
            print(f"ICMP Data: {icmp_header['data']}")
        elif proto == 6 and b"HTTP" in data:  # HTTP (TCP packets with HTTP data)
            print("HTTP Data: ", data.decode('utf-8', errors='ignore'))
        elif proto == 17 and b"DNS" in data:  # DNS (UDP packets with DNS data)
            dns_header = dns_packet(data)
            print(f"DNS Query: {dns_header['query']}")
        
        # Convert raw packet to base64 string and add to the list
        encoded_data = base64.b64encode(raw_data).decode('utf-8')
        exposed_data.append(encoded_data)  # Append processed packet to exposed data list
    except Exception as e:
        print(f"Error processing packet: {e}")

def expose_data():
    while True:
        if not processed_data_queue.empty():
            packet_data = processed_data_queue.get()
            encoded_data = base64.b64encode(packet_data).decode('utf-8')
            exposed_data.append(encoded_data)
            time.sleep(1)

def run_flask():
    # Run the Flask app in a separate thread
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def tcp_segment(data):
    src_port, dest_port, seq, ack, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    data_offset = (offset_reserved_flags >> 12) * 4
    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "seq": seq,
        "ack": ack,
        "data": data[data_offset:]
    }

def udp_segment(data):
    src_port, dest_port, length = struct.unpack('! H H H', data[:6])
    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "data": data[8:]
    }

def icmp_packet(data):
    icmp_type, icmp_code, checksum = struct.unpack('! B B H', data[:4])
    return {
        "type": icmp_type,
        "code": icmp_code,
        "data": data[4:]
    }

def dns_packet(data):
    # DNS Query starts after the UDP header (8 bytes)
    dns_query = data[8:]
    try:
        query_name = dns_query.decode('utf-8', errors='ignore')
    except Exception:
        query_name = "Non-ASCII data"
    return {
        "query": query_name
    }

if __name__ == "__main__":
    main()
