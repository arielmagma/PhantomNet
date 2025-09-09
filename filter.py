from packet_handler import get_protocol, get_ip_dst, get_ip_src, get_port_dst, get_port_src

class Filter:
    def __init__(self):
        self.protocols = ['HTTP', 'HTTPS', 'TCP', 'DNS', 'UDP', 'ICMP', 'ARP', 'Raw', 'IP', 'IPv6', 'SMTP', 'SSH', 'FTP', 'DHCP', 'IGMPv3', 'mDNS', 'Unknown']
        self.filter = []

    def update_filter(self, filter):
        self.tokenize_filter(filter)

    def tokenize_filter(self, filter):
        '''
        Tokenizes the filter -> splits it into different parts and checks if each part is valid
        :param filter: the filter stright from the filter_entry
        :return: None
        '''
        self.filter = filter.split()

        index = 0
        while index < len(self.filter):
            if self.filter[index] == 'ip.src' or self.filter[index] == 'ip.dst':
                if self.filter[index+1] == '==' or self.filter[index+1] == '!=':
                    if len(self.filter) - index > 2:
                        if not self.check_ip(self.filter[index+2]):
                            del self.filter[index:index+3]
                            self.check_logic(index)
                        else:
                            index += 3
                            continue
                    else:
                        del self.filter[index:index+2]
                        self.check_logic(index)
                else:
                    del self.filter[index:index+3]
                    self.check_logic(index)
            elif self.filter[index] == 'port.src' or self.filter[index] == 'port.dst':
                if self.filter[index+1] == '==' or self.filter[index+1] == '!=':
                    if len(self.filter) - index > 2:
                        if not self.check_port(self.filter[index+2]):
                            del self.filter[index:index+3]
                            self.check_logic(index)
                        else:
                            index += 3
                            continue
                    else:
                        del self.filter[index:index+2]
                        self.check_logic(index)
                else:
                    del self.filter[index:index+3]
                    self.check_logic(index)
            elif self.filter[index] == 'id':
                if self.filter[index+1] == '==' or self.filter[index+1] == '!=' or self.filter[index+1] == '>' or self.filter[index+1] == '<':
                    if len(self.filter) - index > 2:
                        if not self.filter[index+2].isdigit():
                            del self.filter[index]
                            self.check_logic(index)
                        else:
                            index += 3
                            continue
                    else:
                        del self.filter[index:index+2]
                        self.check_logic(index)
                else:
                    del self.filter[index:index+3]
                    self.check_logic(index)
            elif self.filter[index] in self.protocols:
                index += 1
            elif self.filter[index] == 'and' or self.filter[index] == 'or':
                if 0 < index < len(self.filter) - 1:
                    index += 1
                else:
                    del self.filter[index]
            elif self.filter[index] == 'not':
                print(index, len(self.filter), self.filter)
                if index < len(self.filter) - 1:
                    index += 1
                else:
                    del self.filter[index]
            else:
                del self.filter[index]

    def check_logic(self, index):
        '''
        Checks if there is a logic expression after deleting an invalid filter
        :param index: the index to check if there's a logic expression
        :return: none
        '''

        if len(self.filter) - index > 0:
            if self.filter[index] == 'and' or self.filter[index] == 'or' or self.filter[index] == 'not':
                del self.filter[index]
        elif index > 0 and index - 1 < len(self.filter):
            if self.filter[index-1] == 'and' or self.filter[index-1] == 'or' or self.filter[index-1] == 'not':
                del self.filter[index-1]

    def check_ip(self, ip):
        '''
        Checks if the ip is an valid ip or not
        :param ip: the ip string to check if valid or not (str)
        :return: if the ip is valid or not (boolean)
        '''

        valid = True

        if ip == 'None':
            valid = True
        elif ':' in ip and len(ip.split(':')) == 8:
            hex = '0123456789ABCDEF'

            for char in ip: # Check if all chars in ip address are in Hex base
                if not ':':
                    if char not in hex:
                        valid = False

        elif not any(char.isdigit() for char in ip):
            valid = False
        else:
            ip_parts = ip.split('.')

            if len(ip_parts) != 4:
                valid = False
            else:
                for part in ip_parts:
                    if int(part) < 0 or int(part) > 255:
                        valid = False

        return valid

    def check_port(self, port):
        '''
        Checks if a port is a valid port
        :param port: the string of the port to check (string)
        :return: if the port is valid or not (boolean)
        '''

        valid = True

        if port == 'None':
            valid = True
        elif not port.isdigit():
            valid = False
        elif int(port) < 0 or int(port) > 65535:
            valid = False

        return valid

    def check_filter(self, packet, filter, index):
        '''
        Checks if a packet fits specific filter from the filters list at the given index, and replaces the filter in the list with the result
        :param packet: the packet to check
        :param filter: the list of filters
        :param index: the index of the current filter to check
        :return: none
        '''

        if filter[index] == 'ip.src' :
            if filter[index+1] == '==':
                filter[index:index+3] = [get_ip_src(packet) == filter[index+2]]
            elif filter[index+1] == '!=':
                filter[index:index+3] = [get_ip_src(packet) != filter[index+2]]
        elif filter[index] == 'ip.dst':
            if filter[index+1] == '==':
                filter[index:index+3] = [get_ip_dst(packet) == filter[index+2]]
            elif filter[index+1] == '!=':
                filter[index:index+3] = [get_ip_dst(packet) != filter[index+2]]
        elif filter[index] == 'port.src':
            if filter[index+1] == '==':
                filter[index:index+3] = [str(get_port_src(packet)) == filter[index+2]]
            elif filter[index+1] == '!=':
                filter[index:index+3] = [str(get_port_src(packet)) != filter[index+2]]
        elif filter[index] == 'port.dst':
            if filter[index+1] == '==':
                filter[index:index+3] = [str(get_port_dst(packet)) == filter[index+2]]
            elif filter[index+1] == '!=':
                filter[index:index+3] = [str(get_port_dst(packet)) != filter[index+2]]
        elif filter[index] == 'id':
            if filter[index+1] == '==':
                filter[index:index+3] = [packet['id'] == int(filter[index+2])]
            elif filter[index+1] == '>':
                filter[index:index+3] = [packet['id'] > int(filter[index+2])]
            elif filter[index+1] == '<':
                filter[index:index+3] = [packet['id'] < int(filter[index+2])]
            elif filter[index+1] == '!=':
                filter[index:index+3] = [packet['id'] != int(filter[index+2])]
        elif filter[index] in self.protocols:
            filter[index] = (packet['protocol'] == filter[index])
        elif filter[index] == '(':
            index2 = filter.index(')', index)
            filter[index:index2+1] = [self.check_filters(packet, filter[index+1:index2])]
        else:
            del(filter[index])

    def check_filters(self, packet):
        self.format_packet(packet)
        filter = self.filter.copy()

        i = 0
        while i < len(filter):
            if filter[i] == 'or':
                self.check_filter(packet, filter, i+1)
                filter[i-1:i+2] = [filter[i-1] or filter[i+1]]
                i -= 1
            elif filter[i] == 'and':
                self.check_filter(packet, filter, i+1)
                filter[i-1:i+2] = [filter[i-1] and filter[i+1]]
                i -= 1
            elif filter[i] == 'not':
                self.check_filter(packet, filter, i+1)
                filter[i:i+2] = [not filter[i+1]]
            else:
                self.check_filter(packet, filter, i)
            i += 1
        if len(filter) < 1:
            return True
        return filter[0]

    def format_packet(self, packet):
        for key in packet.keys():
            if packet[key] is None:
                packet[key] = "None"
