import sys
import dpkt
import socket
from dpkt.compat import compat_ord
from decimal import Decimal

f = open(sys.argv[1], 'rb')
pcap = dpkt.pcap.Reader(f)
#times
times = []
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
    '192.168.0.1':   'f8:1a:67:cd:57:6e',
    '192.168.0.101': '60:fe:c5:9e:63:3c'
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


def is_syn(tcp_data: dpkt.tcp.TCP) -> bool:
    if(type(tcp_data) != dpkt.tcp.TCP):
        return False
    if(tcp_data.flags != 2):
        return False
    return True

def is_udp(protocol_data: dpkt.udp.UDP) -> bool:
    if(type(protocol_data) == dpkt.udp.UDP):
        return True
    return False

def is_tcp_handshake(tcp_data: dpkt.tcp.TCP) -> bool:
    if(type(tcp_data) != dpkt.tcp.TCP):
        return False
    if (tcp_data.flags == dpkt.tcp.TH_CWR | dpkt.tcp.TH_ECE):
        return True
    return False

packet_no = 0
dst_packets= {
  #"192.168.0.100": {"port_nums": [], "packet_nums": []}, #{ip: {"port_nums": [ports], "packet_nums": [packets]}}
  #"192.168.0.103": {"port_nums": [], "packet_nums": []},
  #"192.168.0.1":   {"port_nums": [], "packet_nums": []},
  #"192.168.0.101": {"port_nums": [], "packet_nums": []}
} 
times = {} # {ip: {port: {"packet_nums":[], "times":[]}}}
for ts, buf in pcap:
    #Get packet data
    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data
    protocol = ip.data

    #Arp spoof detection
    if type(ip) == dpkt.arp.ARP and ip.op == dpkt.arp.ARP_OP_REPLY:
        if mac_addr(ip.sha) != devices[inet_to_str(ip.spa)]:
            arpspoof_log.append((mac_addr(ip.sha), mac_addr(ip.tha), packet_no))


    # Portscan Detection
    if(is_syn(protocol) or is_udp(protocol)):
        dst_ip = inet_to_str(ip.dst)
        src_ip = inet_to_str(ip.src)
        srcport = protocol.sport
        dstport = protocol.dport
        
        if(dst_ip not in dst_packets):
            dst_packets[dst_ip] = {"port_nums":[],"packet_nums":[]}
        
        if(dstport not in dst_packets[dst_ip]["port_nums"]):
            dst_packets[dst_ip]["port_nums"].append(dstport)
            dst_packets[dst_ip]["packet_nums"].append(packet_no)

    if(is_syn(protocol)):
        if(not is_tcp_handshake(protocol)):
            if dst_ip not in times:
                times[dst_ip] = {}
            if(dstport not in times[dst_ip]):
                times[dst_ip][dstport] = {"packet_nums": [], "times": []}
            times[dst_ip][dstport]["packet_nums"].append(packet_no)
            times[dst_ip][dstport]["times"].append(ts)
    packet_no += 1

            

#Output results
for arp in arpspoof_log:
    print("ARP spoofing!")
    print("Src MAC: %s" % arp[0])
    print("Dst MAC: %s" % arp[1])
    print("Packet number: %d" % arp[2])

def output_port_scan(values: dict, ip: str) -> None:
    print("Port scan!")
    print("Dst IP: {0}".format(ip))
    print("Packet number: ", end="")
    for idx,packet in enumerate(values["packet_nums"]):
      if idx > 0:
        print(",", end=" ")
      print(packet, end="")

# detecting number of different ports
for ip,packets in dst_packets.items():
    num_ports = len(packets['port_nums'])
    if(num_ports > 100):
    # do your outputting logic here...
        output_port_scan(packets, ip)
        print()




def output_synflood(ip: str, port: int, packets: list) -> None:
    print("SYN floods!")
    print("Dst IP: {0}".format(ip))
    print("Dst Port:", port)
    print("Packet number: ", end="")
    for idx in range(0, len(packets)):
      if idx > 0:
        print(",", end=" ")
      print(packets[idx], end="")
    print()

end_idx = 100
for ip,ports in times.items():
    for port, dicts in ports.items():
        detected = 0
        m_times = times[ip][port]#changes
        detected_packets=[]
        if(len(m_times['times']) > 100):
            for idx,time in enumerate(m_times['times'][:-100]):
                #use the Decimal typing as it doesn't have floating point precision math errors
                #base python will not do accurate math with these doubles/floats
                start_time = Decimal(time)

                # get the end time, same reason as before
                end_time = Decimal(m_times['times'][end_idx])
            
                # FPP subtraction
                total_time = end_time - start_time
                
                #update the ending index)
                end_idx += 1
            
                # if the total time between the 100 packets was less than 1 second, it was a flood
                if(total_time < 1):
                    # syn flood!
                    detected += 1
                    detected_packets.append(m_times['packet_nums'][idx])
                if(detected >= 101):
                    output_synflood(ip,port, detected_packets)#changes
                    break
            
                


#for syn in synflood_log:
#    print("SYN floods")
#    print("Dst IP: %s" % syn[0])
#    print("Dst Port: %d" % syn[1])
#    print("Packet number:", end=" ")
#    for index, packet in enumerate(syn[2]):
#        if index > 0:
#            print(",", end=" ")
#        print(packet, end="")
#    print()
#
f.close()