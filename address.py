

import dpkt
import socket

def printPcap(pcap):
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            # Read the source IP in src
            src = socket.inet_ntoa(ip.src)
            # Read the destination IP in dst
            dst = socket.inet_ntoa(ip.dst)

            # Print the source and destination IP
            print('Source is : ' + src + ' Destination is: ' + dst)

        except:
            pass

def main():
    # Open pcap file for reading
    with open('1.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        printPcap(pcap)

if __name__ == '__main__':
    main()

