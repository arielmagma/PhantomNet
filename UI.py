from threading import *
from time import *
from tkinter import *

class UI:
    def __init__(self, Sniffer):
        self.protocols = ['HTTP', 'HTTPS', 'TCP', 'DNS', 'UDP', 'ICMP', 'ARP', 'Raw', 'IP', 'Unknown']
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
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.setup_widgets()

        self.root.after(100, self.update_packets)
        self.root.mainloop()

    def setup_widgets(self):
        self.title = Label(self.root, text='Welcome to PhantomNet')
        self.title.pack()

        Label(self.root, text = 'Filters: ').pack()
        self.filter_entry = Entry(self.root)
        self.filter_entry.bind('<KeyRelease>', self.get_filter)
        self.filter_entry.pack()

        self.pause_checkbox = Checkbutton(self.root, text='Pause sniffing', variable=self.pause, command=self.on_pause)
        self.pause_checkbox.pack()

        scrollbar = Scrollbar(self.root)
        scrollbar.pack(side=LEFT, fill=Y)
        self.packets_box = Listbox(self.root, yscrollcommand=scrollbar.set, height = 50, width = 125)
        self.packets_box.bind('<Double-Button>', self.open_data)
        self.packets_box.pack(side=LEFT, fill=BOTH)
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
        else:
            self.pause = 0
            self.Sniffer.pause = self.pause
            self.sniffing_thread = Thread(target=self.Sniffer.sniffing).start()
            self.update_packets()

    def get_filter(self, event=None):
        filters = self.filter_entry.get()
        filters = filters.split()

        self.filters = []
        for filter in range(len(filters)):
            if filters[filter] in self.protocols:
                self.filters.append(filters[filter])

        self.filter_change()

    def check_filter(self, packet):
        if len(self.filters) != 0:
            if packet['protocol'] in self.filters:
                return True
            else:
                return False
        else:
            return True

    def filter_change(self):
        self.packets_box.delete(0, END)

        for packet in self.Sniffer.get_packets():
            if self.check_filter(packet):
                self.packets_box.insert(END, self.packet_string(packet))

        self.num_of_packets = len(self.Sniffer.get_packets())

    def packet_string(self, packet):
        return f"{packet['id']}  |  {packet['protocol']}  |  {packet['src_ip']}  |  {packet['src_port']}  |  {packet['dst_ip']}  |  {packet['dst_port']}"

    def update_packets(self):
        new_packets = self.Sniffer.get_packets()[self.num_of_packets:]

        for packet in new_packets:
            if self.check_filter(packet):
                self.packets_box.insert(END, self.packet_string(packet))

        self.num_of_packets += len(new_packets)

        if self.pause == 0:
            self.root.after(100, self.update_packets)

    def open_data(self, event=None):
        selected = self.packets_box.curselection()
        index = int(self.packets_box.get(selected[0]).split()[0])
        packet = self.Sniffer.packets[index]

        print(packet)

        top = Toplevel(self.root)
        top.title(f"Packet #{index}")

        top.geometry("600x400")

        label = Label(top, text=f"Packet #{index} Data:", font=(12))
        label.pack(pady=10)

        data = Label(top, text=packet['data'], font=(6))
        data.pack()
