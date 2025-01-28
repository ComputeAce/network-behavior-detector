import socket
import struct
import logging

# Set up logging to file
logging.basicConfig(
    filename="packet_capture.log",
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# Global variables
packet_count = 0
sent_packet_count = 0
received_packet_count = 0
ip_packet_count = {}  # Tracks sent/received packets per IP

# Protocol mapping
PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}

# Common port-based protocols
PORT_PROTOCOLS = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    25: "SMTP",
    22: "SSH",
    110: "POP3",
    143: "IMAP"
}


def process_packet(raw_data, src_ip, dest_ip, proto, payload):
    """
    Process a packet, extract details, and log statistics.
    """
    global packet_count, sent_packet_count, received_packet_count

    try:
        # Increment packet count
        packet_count += 1

        # Determine the protocol
        protocol_name = PROTOCOLS.get(proto, f"Unknown (Proto {proto})")

        # Analyze TCP/UDP payload for specific port-based protocols
        port_info = ""
        if proto in (6, 17):  # TCP or UDP
            try:
                src_port, dest_port = struct.unpack('! H H', payload[:4])
                port_protocol = PORT_PROTOCOLS.get(src_port) or PORT_PROTOCOLS.get(dest_port)
                if port_protocol:
                    port_info = f"({port_protocol})"
            except Exception:
                pass

        # Update global sent/received counts
        if src_ip == "192.168.1.1":  # Replace with the local IP of your device
            sent_packet_count += 1
        else:
            received_packet_count += 1

        # Update per-IP counts
        if src_ip not in ip_packet_count:
            ip_packet_count[src_ip] = {"sent": 0, "received": 0}
        if dest_ip not in ip_packet_count:
            ip_packet_count[dest_ip] = {"sent": 0, "received": 0}

        ip_packet_count[src_ip]["sent"] += 1
        ip_packet_count[dest_ip]["received"] += 1

        # Log the packet
        log_message = (
            f"Packet from {src_ip} to {dest_ip} | Protocol: {protocol_name} {port_info}\n"
            f"Total Packets: {packet_count} | Sent: {sent_packet_count} | Received: {received_packet_count}"
        )
        print(log_message)
        logging.info(log_message)

    except Exception as e:
        logging.error(f"Error processing packet: {e}")


def ipv4_packet(data):
    """
    Extract IPv4 packet details.
    """
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


def ipv4(addr):
    """
    Convert raw IP address to readable format.
    """
    return '.'.join(map(str, addr))


def capture_packets():
    """
    Capture packets from the network interface.
    """
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind(("0.0.0.0", 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        conn.settimeout(10)
        print("Listening for packets...")
        logging.info("Packet capture started.")

        while True:
            try:
                raw_data, addr = conn.recvfrom(65535)
                version, header_length, ttl, proto, src, target, payload = ipv4_packet(raw_data)
                process_packet(raw_data, src, target, proto, payload)
            except socket.timeout:
                print("Timeout occurred. Listening continues...")
            except Exception as e:
                logging.error(f"Error during packet capture: {e}")
                print(f"Error: {e}")

    except PermissionError:
        print("Permission denied: Run the script with Administrator privileges.")
        logging.error("Permission denied: Run the script with Administrator privileges.")
    except KeyboardInterrupt:
        print(f"\nExiting... Total packets captured: {packet_count}")
        print(f"Sent Packets: {sent_packet_count} | Received Packets: {received_packet_count}")
        logging.info(f"Exiting... Total packets captured: {packet_count}")
        logging.info(f"Sent Packets: {sent_packet_count} | Received Packets: {received_packet_count}")
        exit(0)


if __name__ == "__main__":
    capture_packets()
