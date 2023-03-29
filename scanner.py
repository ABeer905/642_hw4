import sys

f = open(sys.argv[1], 'r')

#Logfiles to output for each attack
#arpspoof list of tuples formatted (src mac, dst mac, packet number)
arpspoof_log = []

#portscan list of tuples formatted (dst ip, list of packets)
portscan_log = []

#synflood list of tuples formatted (dst ip, dst port, list of packets)
synflood_log = []

#TODO: process file

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