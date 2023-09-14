# ***************************Analysing Transmission Control Protocol Packets ************************************

#!/usr/bin/env python3

import dpkt
import socket

def printPcap(pcap):
    total_packets = 0
    tcp_packets = 0
    total_bytes = 0
    total_syn = 0        # synchronization packets
    total_fin = 0        #final packets
    total_reset = 0
    total_ack = 0        #acknowledgement packets
    total_urg = 0        #urgent packets

    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            # Check if the packet is using TCP
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp_packets += 1

                # Check TCP flags
                if ip.data.flags & dpkt.tcp.TH_SYN:
                    total_syn += 1
                if ip.data.flags & dpkt.tcp.TH_FIN:
                    total_fin += 1
                if ip.data.flags & dpkt.tcp.TH_RST:
                    total_reset += 1
                if ip.data.flags & dpkt.tcp.TH_ACK:
                    total_ack += 1
                if ip.data.flags & dpkt.tcp.TH_URG:
                    total_urg += 1

            # Increment total packet count and bytes
            total_packets += 1
            total_bytes += len(buf)

        except:
            pass

    # Print TCP statistics
    print('TCP Statistics:')
    print(f'Total packets: {total_packets}')
    print(f'Total TCP packets: {tcp_packets}')
    print(f'Total bytes: {total_bytes}')
    print(f'Total SYN packets: {total_syn}')
    print(f'Total FIN packets: {total_fin}')
    print(f'Total RST packets: {total_reset}')
    print(f'Total ACK packets: {total_ack}')
    print(f'Total URG packets: {total_urg}')

def main():
    # Open pcap file for reading
    with open('1.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        printPcap(pcap)

if __name__ == '__main__':
    main()