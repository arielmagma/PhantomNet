def Ethernet_decode(packet_data):
    data = {}

    data['Destination MAC'] = f'{packet_data[0:2]}:{packet_data[2:4]}:{packet_data[4:6]}:{packet_data[6:8]}:{packet_data[8:10]}:{packet_data[10:12]}'
    data['Source MAC'] = f'{packet_data[12:14]}:{packet_data[14:16]}:{packet_data[16:18]}:{packet_data[18:20]}:{packet_data[20:22]}:{packet_data[22:24]}'
    data['Protocol'] = int(packet_data[24:28], 16)
    data['Data'] = packet_data[28:]

    return data

def arp_decode(packet_data):
    data = {'HTYPE': int(packet_data[:4], 16), 'PTYPE': int(packet_data[4:8], 16), 'HLEN': int(packet_data[8:10], 16),
            'PLEN': int(packet_data[10:12], 16), 'OPER': int(packet_data[12:16], 16),
            'SHA': f'{packet_data[16:18]}:{packet_data[18:20]}:{packet_data[20:22]}:{packet_data[22:24]}:{packet_data[24:26]}:{packet_data[26:28]}',
            'SPA': f'{int(packet_data[28:30], 16)}.{int(packet_data[30:32], 16)}.{int(packet_data[32:34], 16)}.{int(packet_data[34:36], 16)}',
            'THA': f'{packet_data[36:38]}:{packet_data[38:40]}:{packet_data[40:42]}:{packet_data[42:44]}:{packet_data[44:46]}:{packet_data[46:48]}',
            'TPA': f'{int(packet_data[48:50], 16)}.{int(packet_data[50:52], 16)}.{int(packet_data[52:54], 16)}.{int(packet_data[54:56], 16)}'}
    return data

def IPv6_decode(packet_data):
    data = {}

    first_4_bytes = int(packet_data[0:8], 16)
    data['Version'] = (first_4_bytes >> 28) & 0xF
    data['Traffic Class'] = (first_4_bytes >> 20) & 0xFF
    data['Flow Label'] = first_4_bytes & 0xFFFFF
    data['Payload Length'] = int(packet_data[8:12], 16)
    data['Next Header'] = int(packet_data[12:14], 16)
    data['Hop Limit'] = int(packet_data[14:16], 16)

    data['Source IP'] = f'{packet_data[16:20]}:{packet_data[20:24]}:{packet_data[24:28]}:{packet_data[28:32]}:{packet_data[32:36]}:{packet_data[36:40]}:{packet_data[40:44]}:{packet_data[44:48]}'
    data['Destination IP'] = f'{packet_data[48:52]}:{packet_data[52:56]}:{packet_data[56:60]}:{packet_data[60:64]}:{packet_data[64:68]}:{packet_data[68:72]}:{packet_data[72:76]}:{packet_data[76:80]}'
    data['Data'] = packet_data[80:]

    return data

def IPv4_decode(packet_data):
    data = {'Version': 0, 'IHL': 0, 'Type of Service': int(packet_data[2:4]),
            'Length': int(packet_data[4:8], 16), 'Identification': int(packet_data[8:12], 16),
            'Flags': int(packet_data[12:16], 16), 'TTL': int(packet_data[16:18], 16),
            'Protocol': int(packet_data[18:20], 16), 'Header Checksum': int(packet_data[20:24], 16),
            'Source IP': f'{int(packet_data[24:26], 16)}.{int(packet_data[26:28], 16)}.{int(packet_data[28:30], 16)}.{int(packet_data[30:32], 16)}',
            'Destination IP': f'{int(packet_data[32:34], 16)}.{int(packet_data[34:36], 16)}.{int(packet_data[36:38], 16)}.{int(packet_data[38:40], 16)}'}

    first_byte = int(packet_data[0:2], 16)
    data['Version'] = first_byte >> 4
    data['IHL'] = first_byte & 0x0F

    if data['Protocol'] == 6:
        data['Data'] = tcp_decode(packet_data[data['IHL'] * 4 * 2:])
    elif data['Protocol'] == 17:
        data['Data'] = udp_decode(packet_data[data['IHL'] * 4 * 2:])
    else:
        data['Data'] = packet_data[data['IHL'] * 4 * 2]

    return data

def tcp_decode(packet_data):
    data = {'Source Port': int(packet_data[0:4], 16), 'Destination Port': int(packet_data[4:8], 16),
            'SEQ': int(packet_data[8:16], 16), 'ACK': int(packet_data[16:24], 16)}

    byte_12 = int(packet_data[24:26], 16)
    data['DO'] = byte_12 >> 4
    data['Reserved'] = (byte_12 >> 1) & 0x7
    data['NS'] = byte_12 & 0x1

    flags = int(packet_data[26:28], 16)
    data['Flags'] = {
    'CWR': (flags >> 7) & 1,
    'ECE': (flags >> 6) & 1,
    'URG': (flags >> 5) & 1,
    'ACK': (flags >> 4) & 1,
    'PSH': (flags >> 3) & 1,
    'RST': (flags >> 2) & 1,
    'SYN': (flags >> 1) & 1,
    'FIN': flags & 1 }

    data['Window Size'] = int(packet_data[28:32], 16)
    data['Checksum'] = int(packet_data[32:36], 16)
    data['Urgent Pointer'] = int(packet_data[36:40], 16)

    option_data = packet_data[40:data['DO'] * 4 * 2]

    def get_options(data):
        options = []

        index = 0
        byte = '-1'
        while index < len(data):
            option = {}

            option['Kind'] = int(data[index:index+2], 16)
            index += 2

            if option['Kind'] == 0:
                break

            if option['Kind'] == 1:
                continue

            option['Length'] = int(data[index:index+2], 16)
            index += 2

            data_len = option['Length'] - 2
            if index + data_len*2 > len(data):
                break

            option_data_bytes = data[index:index+data_len*2]
            index += data_len*2

            option_data = ''
            for i in range(0, len(option_data_bytes), 2):
                current_byte = option_data_bytes[i:i+2]
                option_data += current_byte

            if option_data:
                option['Data'] = int(option_data, 16)
            else:
                option['Data'] = 0
            options.append(option)
        return options

    data['Options'] = get_options(option_data)
    data['Data'] = packet_data[data['DO'] * 4 * 2:]
    return data

def udp_decode(packet_data):
    data = {'Source Port': int(packet_data[0:4], 16), 'Destination Port': int(packet_data[4:8], 16),
            'Length': int(packet_data[8:12], 16), 'Checksum': int(packet_data[12:16], 16),
            'Data': bytes.fromhex(packet_data[16:]).decode(errors='ignore')}

    return data

def icmp_decode(packet_data):
    data = {}

    data['Type'] = int(packet_data[0:2], 16)
    data['Code'] = int(packet_data[2:4], 16)
    data['Checksum'] = int(packet_data[4:8], 16)
    data['Rest of Header'] = packet_data[8:16]
    data['Data'] = packet_data[16:]
    return data

handler = {'ARP': arp_decode, 'IPv6':IPv6_decode, 'IPv4': IPv4_decode, 'TCP': tcp_decode, 'UDP': udp_decode, 'Ethernet': Ethernet_decode, 'ICMP': icmp_decode}

def decode(packet):
        return handler[packet['protocol']](packet['data'])
