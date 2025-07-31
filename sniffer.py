from scapy.all import *

class sniffer:
    def __init__(self):
        self.packets = []
        self.pause = 0

    def sniffing(self):
        sniff(prn = self.proccess_packet, stop_filter=self.check_sniffing)

    def check_sniffing(self, packet):
        return self.pause

    def proccess_packet(self, packet):
        protocol, src_ip, dst_ip, src_port, dst_port = self.get_packet_information(packet)
        data = self.get_data(packet)

        self.packets.append({'protocol': protocol, 'src_ip': src_ip, 'src_port': src_port, 'dst_ip': dst_ip, 'dst_port': dst_port, 'id': len(self.packets), 'data': data})

    def get_data(self, packet):
        if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
            print(self.bytes_to_hex(bytes(packet)), '\n\n\n')
        if Raw in packet:
            return self.bytes_to_hex(packet[Raw].load)
        try:
            return self.bytes_to_hex(bytes(packet.payload))
        except Exception:
            return None

    def bytes_to_hex(self, data):
        return data.hex().upper()

    def get_packet_information(self, packet):
        protocol = self.identify_protocol(packet)

        src_ip = None
        dst_ip = None
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

        src_port = None
        dst_port = None
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        return protocol, src_ip, dst_ip, src_port, dst_port

    def identify_protocol(self, packet):
        if packet.haslayer(TCP):
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                return 'HTTP'
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                return 'HTTPS'
            elif packet[TCP].dport == 25 or packet[TCP].sport == 25:
                return 'SMTP'
            elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                return 'SSH'
            elif packet[TCP].dport == 20 or packet[TCP].sport == 20 or packet[TCP].dport == 21 or packet[TCP].sport == 21:
                return 'FTP'
            else:
                return 'TCP'

        elif packet.haslayer(UDP):
            if packet['UDP'].sport == 53 or packet[UDP].dport == 53:
                return 'DNS'
            elif packet[UDP].dport == 67 or packet[UDP].sport == 67 or packet[UDP].dport == 68 or packet[UDP].sport == 68:
                return 'DHCP'
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

        elif packet.haslayer(IPv6):
            return 'IPv6'

        else:
            return 'Unknown'

    def get_packets(self):
        return self.packets
