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
            else:
                return 'UDP'

        elif protocol == 'ICMP':
            return 'ICMP'

        else:
            return 'Unknown'

def get_protocol(packet):
    Data = packet['Data']
    last_protocol = None
    protocol = None

    while isinstance(Data, dict) and 'Data' in Data['Data']:
        if 'Protocol' in Data:
            last_protocol = Data['Protocol']
        elif 'Next Header' in Data:
            last_protocol = Data['Next Header']

        Data = Data['Data']

    if 'Protocol' in Data:
        protocol = Data['Protocol']
    elif 'Next Header' in Data:
        protocol = Data['Next Header']
    else:
        protocol = identify_protocol(Data, last_protocol)

    return protocol

def get_ip_src(packet):
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

def get_raw_data(packet):
    pass

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
