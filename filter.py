#!/usr/bin/env python3

import dpkt
import socket

def printPcap(pcap, protocol):
    total_packets = 0
    protocol_packets = 0
    total_bytes = 0

    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            # Check if the packet matches the filter protocol
            if isinstance(ip.data, protocol):
                # Process the packet
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)

                # Print the source and destination IP
                print('Source: ' + src + ' Destination: ' + dst)

                # Increment protocol-specific packet count and bytes
                protocol_packets += 1
                total_bytes += len(buf)

            # Increment total packet count
            total_packets += 1

        except:
            pass

    # Print protocol-specific statistics
    print(f'{protocol.__name__} Statistics:')
    print(f'Total packets: {total_packets}')
    print(f'Total {protocol.__name__} packets: {protocol_packets}')
    print(f'Total bytes: {total_bytes}')

def main():
    # Open pcap file for reading
    with open('1.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        # Prompt the user for the protocol
        protocol_input = input("Enter the protocol (1 for TCP, 2 for UDP,3 for DNS,4 for ARP): ")
        if protocol_input == "1":
            protocol = dpkt.tcp.TCP
        elif protocol_input == "2":
            protocol = dpkt.udp.UDP

        elif protocol_input == "3":
            protocol = dpkt.dns.DNS

        elif protocol_input == "4":
            protocol = dpkt.arp.ARP
        else:
            print("Invalid input. Exiting...")
            return

        # Filter and print the packets
        printPcap(pcap, protocol)

if __name__ == '__main__':
    main()