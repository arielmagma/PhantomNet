from scapy.all import *

class sniffer:
    def __init__(self):
        self.packets = []

    def sniffing(self):
        sniff(prn = self.proccess_packet)

    def proccess_packet(self, packet):
        protocol, src_ip, dst_ip, src_port, dst_port = self.get_packet_information(packet)
        #print(f'{{\'protocol\': {protocol}, \'src_ip\': {src_ip}, \'src_port\': {src_port}, \'dst_ip\': {dst_ip}, \'dst_port\': {dst_port}}}')
        self.packets.append({'protocol': protocol, 'src_ip': src_ip, 'src_port': src_port, 'dst_ip': dst_ip, 'dst_port': dst_port})
        print(self.packets)

    def get_packet_information(self, packet):
        protocol = self.identify_protocol(packet)

        src_ip = None
        dst_ip = None
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        src_port = None
        dst_port = None
        if protocol == 'TCP':
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif protocol == 'UDP':
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        return protocol, src_ip, dst_ip, src_port, dst_port

    def identify_protocol(self, packet):
        if packet.haslayer(TCP):
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                return 'HTTP'
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                return 'HTTPS'
            else:
                return 'TCP'

        elif packet.haslayer(UDP):
            if packet['UDP'].sport == 53 or packet[UDP].dport == 53:
                return 'DNS'
            else:
                return 'UDP'

        elif packet.haslayer(ICMP):
            return 'ICMP'

        elif packet.haslayer(ARP):
            return 'ARP'

        elif packet.haslayer(Raw):
            return 'Raw'

        elif packet.haslayer(IP):
            return 'IP'

        else:
            return 'Unknown'
