from scapy.all import *

FILTERS = []

def main():
    running = True

    while running:
        sniffing()
        if input('Continue running? ').lower() != 'y':
            running = False

def sniffing():
    sniff(lfilter = filter_packet, prn = proccess_packet)

def filter_packet(packet):
    existing_protocols = [
        'TCP', 'UDP'
    ]
    protocol_filter = None

    for filter in FILTERS:
        if filter in existing_protocols:
            protocol_filters = filter

    if protocol_filter != None:
        print('Filter != None')
        if packet.haslayer(protocol_filter):
            return True
    else:
        return True

def proccess_packet(packet):
    protocol = identify_protocol(packet)
    print_packet(packet)

def identify_protocol(packet):
    if packet.haslayer('TCP'):
        return 'TCP'
    elif packet.haslayer('UDP'):
        return 'UDP'
    else:
        return None

def print_packet(packet):
    if packet.haslayer(IP):
        print(f'Src IP: {packet[IP].src}, Dst IP: {packet[IP].dst}')

        if packet.haslayer(TCP):
            print(f'Src Port: {packet[TCP].sport}, Dst Port: {packet[TCP].dport}\n{"-" * 25}\n')
        if packet.haslayer(UDP):
            print(f'Src Port: {packet[UDP].sport}, Dst Port: {packet[UDP].dport}\n{"-" * 25}\n')

if __name__ == "__main__":
    main()
