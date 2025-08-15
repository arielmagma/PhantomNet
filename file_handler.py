from tkinter import filedialog
from datetime import datetime
from decoder import get_first_layer, decode

def binary(text):
    return text.encode('utf-8')

def ascii(text):
    return text.decode('utf-8')

def hex_to_bin(hex):
    result = bytearray()

    for i in range(0, len(hex), 2):
        byte = int(hex[i:i+2], 16)
        result.append(byte)

    return result

def bin_to_hex(bin):
    hex_chars = "0123456789ABCDEF"
    result = []

    for byte in bin:
        high_bits = byte >> 4
        low_bits = byte & 0x0F
        result.append(hex_chars[high_bits])
        result.append(hex_chars[low_bits])
    return ''.join(result)

def save_session(packets):
    path = filedialog.asksaveasfilename(defaultextension=".pnet")

    if not path:
        return

    file = open(path, 'wb')

    file.write(binary('PHNT|'))

    version = '1.0'
    file.write(binary(f'{version}|'))

    name = path.split('/')[-1]
    file.write(binary(f'{name}|'))

    date = datetime.now().date()
    file.write(binary(f'{date}|'))

    length = len(packets)
    file.write(binary(f'{length}'))

    for packet in packets:
        file.write(b'\n\n')
        file.write(hex_to_bin(packet["Hex"]))

    file.close()

def load_session():
    path = filedialog.askopenfilename(defaultextension='.pnet')
    if not path:
        return

    file = open(path, 'rb')
    data = file.read().split(b'\n\n')
    file.close()

    file_information = data[0].split(b'|')
    if ascii(file_information[0]) =='PHNT':
        return loader[ascii(file_information[1])](int(ascii(file_information[-1])), data[1:])

def load_version_1(num_packets, packets):
    packets_list = []

    for packet in range(num_packets):
        hex = bin_to_hex(packets[packet])
        packet_dict = {'id': packet, 'protocol': get_first_layer(hex), 'Data': decode(hex, get_first_layer(hex)),'Hex': hex}
        print(packet_dict['Data'])
        packets_list.append(packet_dict)
        print(packets_list[-1])

    return packets_list

loader = {'1.0': load_version_1,}
