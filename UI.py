from threading import *
from tkinter import *

## Color pallet:
# Black: #000000
# Dark Gray: #323232
# Dark Red: #640000
# Dark Green: #004b00

class UI:
    def __init__(self, Sniffer):
        self.protocols = ['HTTP', 'HTTPS', 'TCP', 'DNS', 'UDP', 'ICMP', 'ARP', 'Raw', 'IP', 'IPv6', 'SMTP', 'SSH', 'FTP', 'DHCP', 'Unknown']
        self.root = None
        self.title = None
        self.filter_entry = None
        self.packets_box = None

        self.Sniffer = Sniffer
        self.filters = []
        self.pause = 0

        self.num_of_packets = 0
        self.sniffing_thread = Thread(target=self.Sniffer.sniffing).start()

        self.setup_window()

    def setup_window(self):
        self.root = Tk()
        self.root.title('PhantomNet')
        self.root.geometry('750x400')
        self.root.config(bg='#000000')
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.setup_widgets()

        self.root.after(100, self.update_packets)
        self.root.mainloop()

    def setup_widgets(self):
        self.filter_frame = Frame(self.root, bg='#000000')
        self.filter_frame.pack(anchor='n', pady=10)
        Label(self.filter_frame, text = 'Filters: ', font=(5), bg='#000000', fg='white').pack(side=LEFT)
        self.filter_entry = Entry(self.filter_frame)
        self.filter_entry.pack(side=RIGHT)
        self.filter_button = Button(self.filter_frame, text='Filter', command=self.get_filter)
        self.filter_button.pack(side=RIGHT)

        self.button_frame = Frame(self.root, bg='#000000')
        self.button_frame.pack(anchor='nw')
        self.pause_button = Button(self.button_frame, text='Pause', command=self.on_pause, bg='#004b00', fg='black')
        self.pause_button.pack(side=LEFT, padx=5, pady=5)
        self.clear_button = Button(self.button_frame, text='Clear', command=self.on_clear, bg='#640000', fg='black')
        self.clear_button.pack(side=LEFT, padx=5, pady=5)

        scrollbar = Scrollbar(self.root, bg='#323232')
        scrollbar.pack(side=RIGHT, fill=Y, padx=5, pady=5)
        self.packets_box = Listbox(self.root, yscrollcommand=scrollbar.set, height = 50, width = 120, bg='#323232', fg='white')
        self.packets_box.bind('<Double-Button>', self.open_data)
        self.packets_box.pack(side=LEFT, fill=BOTH, expand=True, padx=5, pady=5)
        scrollbar.config(command=self.packets_box.yview)

    def on_close(self):
        self.pause = 1
        self.Sniffer.pause = 1

        if self.sniffing_thread and self.sniffing_thread.is_alive():
            self.sniffing_thread.join()

        self.root.destroy()

    def on_pause(self):
        if self.pause == 0:
            self.pause = 1
            self.Sniffer.pause = self.pause
            self.pause_button.config(bg='#640000')
        else:
            self.pause = 0
            self.Sniffer.pause = self.pause
            self.sniffing_thread = Thread(target=self.Sniffer.sniffing).start()
            self.update_packets()
            self.pause_button.config(bg='#006400')

    def on_clear(self):
        self.packets_box.delete(0, END)
        self.Sniffer.packets = []
        self.num_of_packets = 0

    def get_filter(self, event=None):
        self.filters = self.filter_entry.get().split()
        print(self.filters)
        self.filter_change()

    def check_filter(self, packet, filter, index):
        if filter[index] == 'ip.src' and filter[index+1] == '=' and type(filter[index+2]) == str:
            filter[index:index+3] = [(packet['src_ip'] == filter[index+2])]
        elif filter[index] == 'ip.dst' and filter[index+1] == '=' and type(filter[index+2]) == str:
            filter[index:index+3] = [(packet['dst_ip'] == filter[index+2])]
        elif filter[index] == 'port.src' and filter[index+1] == '=' and type(filter[index+2]) == str:
            filter[index:index+3] = [packet['src_port'] == int(filter[index+2])]
        elif filter[index] == 'port.dst' and filter[index+1] == '=' and type(filter[index+2]) == str:
            filter[index:index+3] = [packet['dst_port'] == int(filter[index+2])]
        else:
            del(filter[index])

    def check_filters(self, packet):
        i = 0
        filter = self.filters.copy()
        while i < len(filter):
            if filter[i] == 'or':
                self.check_filter(packet, filter, i+1)
                filter[i-1:i+2] = [filter[i-1] or filter[i+1]]
                i -= 1
            elif filter[i] == 'and':
                self.check_filter(packet, filter, i+1)
                filter[i-1:i+2] = [filter[i-1] and filter[i+1]]
                i -= 1
            else:
                self.check_filter(packet, filter, i)
            i += 1
        if len(filter) < 1:
            return True
        return filter[0]

    def filter_change(self):
        self.packets_box.delete(0, END)

        for packet in self.Sniffer.get_packets():
            if self.check_filters(packet):
                self.packets_box.insert(END, self.packet_string(packet))

        self.num_of_packets = len(self.Sniffer.get_packets())

    def packet_string(self, packet):
        return f"{packet['id']}  |  {packet['protocol']}  |  {packet['src_ip']}  |  {packet['src_port']}  |  {packet['dst_ip']}  |  {packet['dst_port']}"

    def update_packets(self):
        new_packets = self.Sniffer.get_packets()[self.num_of_packets:]

        for packet in new_packets:
            if self.check_filters(packet):
                self.packets_box.insert(END, self.packet_string(packet))

        self.num_of_packets += len(new_packets)

        if self.pause == 0:
            self.root.after(100, self.update_packets)

    def open_data(self, event=None):
        def next_packet():
            nonlocal index
            if index < len(self.Sniffer.packets) - 1:
                index += 1
                top.title(f"Packet #{index}")
                label.config(text=f"Packet #{index} Data:")
                packet = self.Sniffer.packets[index]
                raw_data = packet.get('data', b'')
                if isinstance(raw_data, bytes):
                    formatted_data = ' '.join(f"{byte:02X}" for byte in raw_data)
                else:
                    formatted_data = str(raw_data)
                text.config(state="normal")
                text.delete("1.0", END)
                text.insert(END, formatted_data)
                text.config(state="disabled")
        def back_packet():
            nonlocal index
            if index > 0:
                index -= 1
                top.title(f"Packet #{index}")
                label.config(text=f"Packet #{index} Data:")
                packet = self.Sniffer.packets[index]
                raw_data = packet.get('data', b'')
                if isinstance(raw_data, bytes):
                    formatted_data = ' '.join(f"{byte:02X}" for byte in raw_data)
                else:
                    formatted_data = str(raw_data)
                text.config(state="normal")
                text.delete("1.0", END)
                text.insert(END, formatted_data)
                text.config(state="disabled")

        selected = self.packets_box.curselection()
        index = int(self.packets_box.get(selected[0]).split()[0])
        packet = self.Sniffer.packets[index]

        top = Toplevel(self.root)
        top.title(f"Packet #{index}")

        top.geometry("750x500")

        label = Label(top, text=f"Packet #{index} Data:", font=(12))
        label.pack(pady=10)

        button_frame = Frame(top)
        button_frame.pack(pady=10, padx=10)

        next_button = Button(button_frame, text='Next', command=next_packet)
        next_button.pack(side=RIGHT, padx=10)
        back_button = Button(button_frame, text='Back', command=back_packet)
        back_button.pack(side=LEFT, padx=10)

        frame = Frame(top)
        frame.pack(expand=True, fill=BOTH, padx=10, side=TOP)

        scrollbar = Scrollbar(frame)
        scrollbar.pack(side=RIGHT, fill=Y)

        text = Text(frame, wrap="word", yscrollcommand=scrollbar.set, font=(10))
        text.pack(expand=True, fill=BOTH)

        scrollbar.config(command=text.yview)

        raw_data = packet['data']
        if isinstance(raw_data, bytes):
            formatted_data = ' '.join(f"{byte:02X}" for byte in raw_data)
        else:
            formatted_data = str(raw_data)

        text.insert(END, formatted_data)
        text.config(state="disabled")
