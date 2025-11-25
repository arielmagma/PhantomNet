def identify_protocol(data, protocol):
        if protocol == 'TCP':
            if data['Source Port'] == 80 or data['Destination Port'] == 80:
                return 'HTTP'
            elif data['Source Port'] == 443 or data['Destination Port'] == 443:
                return 'HTTPS'
            else:
                return 'TCP'

        elif protocol == 'UDP':
            if data['Source Port'] == 53 or data['Destination Port'] == 53:
                return 'DNS'
            elif data['Source Port'] == 5353 or data['Destination Port'] == 5353:
                return 'mDNS'
            else:
                return 'UDP'

        elif protocol == 'ICMP':
            return 'ICMP'

        else:
            return 'Unknown'

def get_protocol(packet, first_protocol = None):
    Data = packet
    layers = []

    if first_protocol:
        layers.append(first_protocol)

    while isinstance(Data, dict) and 'Data' in Data['Data']:
        if 'Protocol' in Data:
            layers.append(Data['Protocol'])
        elif 'Next Header' in Data:
            layers.append(Data['Next Header'])

        Data = Data['Data']

    if 'Protocol' in Data:
        protocol = Data['Protocol']
        layers.append(protocol)
    elif 'Next Header' in Data:
        protocol = Data['Next Header']
        layers.append(protocol)
    else:
        if layers:
            protocol = identify_protocol(Data, layers[-1])
        else:
            protocol = identify_protocol(Data, None)

    if layers and layers[-1] != protocol:
        layers.append(protocol)
    elif not layers:
        layers.append(protocol)

    if first_protocol:
        return protocol, layers
    else:
        return protocol

def get_ip_src(packet):
    print(f'Packet Data: {packet}')
    data = packet['Data']

    while isinstance(data, dict):
        if 'Source IP' in data:
            return data['Source IP']
        else:
            data = data['Data']

    return 'None'

def get_ip_dst(packet):
    data = packet['Data']

    while isinstance(data, dict):
        if 'Destination IP' in data:
            return data['Destination IP']
        else:
            data = data['Data']

    return 'None'

def get_port_src(packet):
    data = packet['Data']

    while isinstance(data, dict):
        if 'Source Port' in data:
            return data['Source Port']
        else:
            data = data['Data']

    return 'None'

def get_port_dst(packet):
    data = packet['Data']

    while isinstance(data, dict):
        if 'Destination Port' in data:
            return data['Destination Port']
        else:
            data = data['Data']

    return 'None'

def get_packet_data(data):
    ip_src = None
    ip_dst = None
    port_src = None
    port_dst = None
    protocol = None

    if data == 'None':
        return

    protocol = get_protocol(data)

    while isinstance(data, dict):
        if 'Source IP' in data or 'Destination IP' in data:
            ip_src = data['Source IP']
            ip_dst = data['Destination IP']
        if 'Source Port' in data or 'Destination Port' in data:
            port_src = data['Source Port']
            port_dst = data['Destination Port']

        if 'Data' in data:
            data = data['Data']

    if ip_src is None:
        ip_src = 'None'
    if ip_dst is None:
        ip_dst = 'None'
    if port_src is None:
        port_src = 'None'
    if port_dst is None:
        port_dst = 'None'

    return ip_src, ip_dst, port_src, port_dst, protocol

def hex_dump(data):
    raw_data = ''
    for y in range(0, len(data), 16):
        hex_data = ''
        ascii_data = ''
        for i in range(y, y+16, 2):
            hex_data += f'{data[i:i+2]} '

            if data[i:i+2] == '':
                continue
            value = int(data[i:i+2], 16)
            if  32 <= value <= 126:
                ascii_data += f'{chr(value)} '
            else:
                ascii_data += '• '
        hex_data += '\t'
        ascii_data += '\n'
        hex_data = hex_data.ljust(25)

        raw_data += hex_data + ascii_data

    return raw_data

def find_tcp_conv(packets, packet_index, event=None):
    packet = packets[packet_index]

    if 'tcp' in packet['protocol layers']:
        pass
