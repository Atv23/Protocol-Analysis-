import dpkt
import numpy as np
import matplotlib.pyplot as plt

# Function to extract packet count from an Ethernet frame
def extract_packet_count(eth_frame):
    try:
        eth = dpkt.ethernet.Ethernet(eth_frame)
        if isinstance(eth.data, dpkt.ip.IP):
            # Modify this based on your actual packet structure
            packet_count = eth.data.len  # Assuming len represents packet count
            return packet_count
    except Exception as e:
        pass  # Ignore non-IP packets
    return None

# Function to read packet counts from a .pcap file
def read_packet_counts_from_pcap(file_path):
    packet_counts = []
    
    with open(file_path, 'rb') as pcap_file:
        pcap = dpkt.pcap.Reader(pcap_file)
        
        for timestamp, buf in pcap:
            packet_count = extract_packet_count(buf)
            if packet_count is not None:
                packet_counts.append(packet_count)
    
    return packet_counts

# Load packet counts from the .pcap file
pcap_file_path = '1.pcap'
packet_counts = read_packet_counts_from_pcap(pcap_file_path)

# Define a threshold for anomaly detection (you can adjust this)
threshold = 150

# Detect anomalies
anomalies = [count for count in packet_counts if count > threshold]

# Plot the packet counts and mark anomalies
plt.plot(packet_counts, label='Packet Counts')
plt.plot(range(len(packet_counts)), [threshold] * len(packet_counts), 'r--', label='Threshold')
plt.scatter([i for i, count in enumerate(packet_counts) if count > threshold], [count for count in packet_counts if count > threshold], c='red', marker='x', label='Anomalies')
plt.xlabel('Time')
plt.ylabel('Packet Count')
plt.legend()
plt.title('Packet Count Anomaly Detection')
plt.show()

# Print detected anomalies
print(f'Detected Anomalies: {anomalies}')
