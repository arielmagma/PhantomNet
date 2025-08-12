from scapy.all import *
from decoder import get_first_layer, decode

class sniffer:
    def __init__(self):
        self.packets = []
        self.pause = 0

    def sniffing(self):
        sniff(prn = self.proccess_packet, stop_filter=self.check_sniffing)

    def check_sniffing(self, packet):
        return self.pause

    def proccess_packet(self, packet):
        packet_data = self.bytes_to_hex(bytes(packet))
        protocol = get_first_layer(packet_data)
        data = decode(packet_data, protocol)
        self.packets.append({'id': len(self.packets), 'protocol': protocol, 'Data': data})

    def get_data(self, packet):
        try:
            return self.bytes_to_hex(bytes(packet.payload))
        except Exception:
            return None

    def bytes_to_hex(self, data):
        return data.hex().upper()

    def get_packets(self):
        return self.packets

    def set_packets(self, packets):
        self.packets = packets
