from scapy.all import sniff, IP, UDP, TCP, Ether
import logging

# Setup logging
logging.basicConfig(filename="packet_capture.log", level=logging.INFO, format='%(asctime)s - %(message)s')

# Global variables to track total sent and received packets
total_sent = 0
total_received = 0

# This function will be called for each packet captured
def packet_callback(packet):
    global total_sent, total_received
    
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_src = packet[IP].src  # Source IP address
        ip_dst = packet[IP].dst  # Destination IP address
        protocol = packet[IP].proto  # Protocol number (TCP, UDP, etc.)
        
        # Log the packet details to file
        log_message = f"Packet from {ip_src} to {ip_dst} with protocol {protocol}"
        logging.info(log_message)
        print(log_message)
        
        # Check if the packet is UDP and display UDP source and destination ports
        if packet.haslayer(UDP):
            udp_src_port = packet[UDP].sport
            udp_dst_port = packet[UDP].dport
            log_message = f"  UDP Source Port: {udp_src_port} | Destination Port: {udp_dst_port}"
            logging.info(log_message)
            print(log_message)
        
        # Check if the packet is TCP and display TCP source and destination ports
        elif packet.haslayer(TCP):
            tcp_src_port = packet[TCP].sport
            tcp_dst_port = packet[TCP].dport
            log_message = f"  TCP Source Port: {tcp_src_port} | Destination Port: {tcp_dst_port}"
            logging.info(log_message)
            print(log_message)
        
        # Increment the total packets count
        total_received += 1
        log_message = f"Total Packets Processed: {total_sent + total_received}"
        logging.info(log_message)
        print(log_message)
        log_message = f"Sent Packets: {total_sent} | Received Packets: {total_received}"
        logging.info(log_message)
        print(log_message)
    
    # You can also check if the packet is outgoing (sent by your machine)
    elif packet.haslayer(Ether) and packet[Ether].src == "your_mac_address":  # Replace with your MAC address
        total_sent += 1
        log_message = f"Sent Packet from MAC: {packet[Ether].src}"
        logging.info(log_message)
        print(log_message)

# Function to start sniffing packets
def start_sniffing():
    print("Starting packet capture...")
    sniff(prn=packet_callback, store=0)
