#!/usr/bin/env python3

import dpkt
import socket

def printPcap(pcap):
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            # Check if the packet is using TCP or UDP
            if isinstance(ip.data, dpkt.tcp.TCP):
                transport_layer = "TCP"
                src_port = ip.data.sport
                dst_port = ip.data.dport
                protocol_header = ip.data
            elif isinstance(ip.data, dpkt.udp.UDP):
                transport_layer = "UDP"
                src_port = ip.data.sport
                dst_port = ip.data.dport
                protocol_header = ip.data
            else:
                # Skip packets that are not TCP or UDP
                continue

            # Read the source IP in src
            src = socket.inet_ntoa(ip.src)
            # Read the destination IP in dst
            dst = socket.inet_ntoa(ip.dst)

            # Print the source and destination IP and port numbers
            print('Source: ' + src + ' Port: ' + str(src_port) +
                  ' Destination: ' + dst + ' Port: ' + str(dst_port))

            # Print the protocol header
            print(f'{transport_layer} Header: {repr(protocol_header)}')
            print()

        except:
            pass

def main():
    # Open pcap file for reading
    with open('1.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        printPcap(pcap)

if __name__ == '__main__':
    main()