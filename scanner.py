import sys
import dpkt
import socket
from dpkt.compat import compat_ord

f = open(sys.argv[1], 'rb')
pcap = dpkt.pcap.Reader(f)

#Logfiles to output for each attack
#arpspoof list of tuples formatted (src mac, dst mac, packet number)
arpspoof_log = []

#portscan list of tuples formatted (dst ip, list of packets)
portscan_log = []

#synflood list of tuples formatted (dst ip, dst port, list of packets)
synflood_log = []

#Network's ip/mac combos
devices = {
    '192.168.0.100': '7c:d1:c3:94:9e:b8',
    '192.168.0.103': 'd8:96:95:01:a5:c9',
    '192.168.0.1':   'f8:1a:67:cd:57:6e'
}

def mac_addr(address):
    """
    source: https://dpkt.readthedocs.io/en/latest/_modules/examples/print_icmp.html?highlight=mac_addr
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)

def inet_to_str(inet):
    """
    source: https://dpkt.readthedocs.io/en/latest/_modules/examples/print_icmp.html?highlight=inet_to_str
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

packet_no = 0
for ts, buf in pcap:
    #Get packet data
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    tcp = ip.data

    #Arp spoof detection
    if type(ip) == dpkt.arp.ARP and ip.op == dpkt.arp.ARP_OP_REPLY:
        if mac_addr(ip.sha) != devices[inet_to_str(ip.spa)]:
            arpspoof_log.append((mac_addr(ip.sha), mac_addr(ip.tha), packet_no))

    #TODO: portscan detection
    #TODO: synflood detection
    packet_no += 1
            

#Output results
for arp in arpspoof_log:
    print("ARP spoofing!")
    print("Src MAC: %s" % arp[0])
    print("Dst MAC: %s" % arp[1])
    print("Packet number: %d" % arp[2])

for portl in portscan_log:
    print("Port scan!")
    print("Dst IP: %s" % portl[0])
    print("Packet number:", end=" ")
    for index, packet in enumerate(portl[1]):
        if index > 0:
            print(",", end=" ")
        print(packet, end="")
    print()

for syn in synflood_log:
    print("SYN floods!")
    print("Dst IP: %s" % syn[0])
    print("Dst Port: %d" % syn[1])
    print("Packet number:", end=" ")
    for index, packet in enumerate(syn[2]):
        if index > 0:
            print(",", end=" ")
        print(packet, end="")
    print()

f.close()