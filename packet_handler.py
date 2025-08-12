def get_packet_data(data):
    ip_src = None
    ip_dst = None
    port_src = None
    port_dst = None
    protocol = None

    # Need to add logic to find last protocol. for example tcp when ethernet -> ipv4 -> tcp.
    if data['Protocol'] == 'IPv4' or data['Protocol'] == 'IPv6':
        ip_layer = data['Data']
        ip_src = ip_layer['Source IP']
        ip_dst = ip_layer['Destination IP']

        if 'Protocol' in ip_layer.keys():
            if ip_layer['Protocol'] == 'TCP' or ip_layer['Protocol'] == 'UDP':
                transport_layer = ip_layer['Data']
                port_src = transport_layer['Source Port']
                port_dst = transport_layer['Destination Port']
        elif 'Next Header' in ip_layer.keys():
            if ip_layer['Next Header'] == 'TCP' or ip_layer['Next Header'] == 'UDP':
                transport_layer = ip_layer['Data']
                port_src = transport_layer['Source Port']
                port_dst = transport_layer['Destination Port']

    return ip_src, ip_dst, port_src, port_dst, protocol
