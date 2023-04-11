Scanner usage:
$ python3 scanner.py <input_pcap>

Example:
$ python3 scanner.py HW4/2_attack/arpspoofing.pcap

Output to a file:
$ python3 scanner.py example.pcap > out.txt

Explanations:

Arpspoofing:
The arpspoof scanner checks to see if an Arp request is replied with a mac address different to the known mac address for a given ip. 

Port scanning:
Looks through the syn and udp packets for 100 ports being sent to, and reports the IP of the target machine.

synflood:
Looks through non handshake syns and finds when over 100 are being sent in under a second, and reports the first syn up to 101
