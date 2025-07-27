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
        #print(f'{{\'protocol\': {protocol}, \'src_ip\': {src_ip}, \'src_port\': {src_port}, \'dst_ip\': {dst_ip}, \'dst_port\': {dst_port}, \'id\': {len(self.packets)}}}')
        self.packets.append({'protocol': protocol, 'src_ip': src_ip, 'src_port': src_port, 'dst_ip': dst_ip, 'dst_port': dst_port, 'id': len(self.packets), 'data': data})

    def get_data(self, packet):
        if Raw in packet:
            return self.bytes_to_hex(packet[Raw].load)
        try:
            return bytes(packet.payload)
        except Exception:
            return None

    def bytes_to_hex(self, data, width=8):
        lines = []
        for offset in range(0, len(data), width):
            chunk = data[offset:offset + width]
            hex_bytes = ' '.join(f"{b:02X}" for b in chunk)
            hex_bytes_padded = hex_bytes.ljust(width * 3 - 1)
            ascii_bytes = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            lines.append(f"{offset:04X}  {hex_bytes_padded}  {ascii_bytes}")
        return '\n'.join(lines)

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

    def get_packets(self):
        return self.packets
