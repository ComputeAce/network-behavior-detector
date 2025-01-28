import socket
import struct
import base64
import threading
import queue
import time

# Queues to hold data
processed_data_queue = queue.Queue()

# A list to hold the packet data for exposing over HTTP
exposed_data = []

# Counter to track the number of packets
packet_count = 0
sent_packet_count = 0
received_packet_count = 0

# Dictionary to track packets sent and received from each IP
ip_packet_count = {}

def process_packet(raw_data, src_ip, dest_ip):
    global packet_count, sent_packet_count, received_packet_count
    try:
        # Increment packet count
        packet_count += 1
        print(f"Total Packets Processed: {packet_count}")

        # Update the IP packet count
        if src_ip not in ip_packet_count:
            ip_packet_count[src_ip] = {"sent": 0, "received": 0}
        if dest_ip not in ip_packet_count:
            ip_packet_count[dest_ip] = {"sent": 0, "received": 0}

        # Determine if the packet is incoming or outgoing
        if dest_ip == "0.0.0.0":  # This is likely an outgoing packet
            sent_packet_count += 1
            ip_packet_count[src_ip]["sent"] += 1
        else:  # It's a received packet
            received_packet_count += 1
            ip_packet_count[dest_ip]["received"] += 1

        # Display the packet count for each IP
        print(f"Sent Packets: {sent_packet_count} | Received Packets: {received_packet_count}")
        for ip, counts in ip_packet_count.items():
            print(f"IP {ip} Sent: {counts['sent']} | Received: {counts['received']}")
        
        version, header_length, ttl, proto, src, target, data = ipv4_packet(raw_data)
        print(f"Packet from {src} to {target} with protocol {proto}")
        
        # Handle different protocols
        if proto == 6:  # TCP
            tcp_header = tcp_segment(data)
            print(f"TCP Source Port: {tcp_header['src_port']} Destination Port: {tcp_header['dest_port']}")
        elif proto == 17:  # UDP
            udp_header = udp_segment(data)
            print(f"UDP Source Port: {udp_header['src_port']} Destination Port: {udp_header['dest_port']}")
        elif proto == 1:  # ICMP
            icmp_header = icmp_packet(data)
            print(f"ICMP Type: {icmp_header['type']} Code: {icmp_header['code']}")

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
            # Avoid heavy CPU usage by adding a small delay
            time.sleep(0.01)  # Tune this delay as needed

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

def capture_packets():
    try:
        # Create the raw socket to listen to network packets
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind(("0.0.0.0", 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        conn.settimeout(10)
        print("Listening for packets...")

        # Start a separate thread to expose processed data
        expose_thread = threading.Thread(target=expose_data)
        expose_thread.daemon = True
        expose_thread.start()

        while True:
            try:
                raw_data, addr = conn.recvfrom(65535)  # Capture raw data packets
                print(f"\nPacket received from {addr}:")
                process_packet(raw_data, addr[0], "0.0.0.0")  # Processing packet, change "0.0.0.0" as needed

                # Add the processed data to the queue
                processed_data_queue.put(raw_data)

            except socket.timeout:
                print("No packets received within the timeout period. Continuing to listen...")
            except Exception as e:
                print(f"Error during packet capture: {e}")
                continue

    except PermissionError:
        print("Permission denied: Run the script with Administrator privileges.")
    except OSError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print(f"\nExiting... Total packets captured: {packet_count}")
        print(f"Sent Packets: {sent_packet_count} | Received Packets: {received_packet_count}")
        exit(0)

