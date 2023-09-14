import dpkt
import socket

def printPcap(pcap):
    total_packets = 0
    udp_packets = 0
    total_bytes = 0

    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            # Check if the packet is using UDP
            if isinstance(ip.data, dpkt.udp.UDP):
                udp_packets += 1

            # Increment total packet count and bytes
            total_packets += 1
            total_bytes += len(buf)

        except:
            pass

    # Print UDP statistics
    print('UDP Statistics:')
    print(f'Total packets: {total_packets}')
    print(f'Total UDP packets: {udp_packets}')
    print(f'Total bytes: {total_bytes}')

def main():
    # Open pcap file for reading
    with open('1.pcap', 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        printPcap(pcap)

if __name__ == '__main__':
    main()