from threading import Thread
from tkinter import *
from tkinter import ttk
import time

## Color pallet:
# Black: #000000
# Dark Gray: #232323
# Dark Red: #640000
# Dark Green: #004b00
# Text: #fafafa

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
        self.root.geometry('950x500')
        self.root.config(bg='#000000')
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.menu_bar = Menu(self.root, bg='#232323', fg='#fafafa', relief='flat')
        file_menu = Menu(self.menu_bar, tearoff=0, bg='#232323', fg='#fafafa')
        file_menu.add_command(label='Exit', command=self.root.quit)
        self.menu_bar.add_cascade(label='File', menu=file_menu)
        help_menu = Menu(self.menu_bar, tearoff=0, bg='#232323', fg='#fafafa')
        help_menu.add_command(label='About', command=lambda: self.show_about())
        self.menu_bar.add_cascade(label='Help', menu=help_menu)
        self.root.config(menu=self.menu_bar)

        self.setup_widgets()

        self.root.after(100, self.update_packets)
        self.root.mainloop()

    def setup_widgets(self):
        top_panel = Frame(self.root, bg='#232323')
        top_panel.pack(fill='x', padx=0, pady=0)

        filter_frame = Frame(top_panel, bg='#232323')
        filter_frame.pack(side=LEFT, padx=15, pady=12)

        Label(filter_frame, text = 'Filters: ', font=('Segoe UI', 11, 'bold'), bg='#232323', fg='#fafafa').pack(side=LEFT, padx=(0, 8))
        self.filter_entry = Entry(filter_frame, font=('Segoe UI', 10), width=30, bg='#000000', fg='#ffffff', insertbackground='#fafafa', relief='flat')
        self.filter_entry.bind('<Return>', self.get_filter)
        self.filter_entry.pack(side=LEFT)
        self.filter_button = Button(filter_frame, text='Filter', font=('Segoe UI', 10, 'bold'), command=self.get_filter, bg='#640000', fg='#fafafa', activebackground='#a03c3c', activeforeground='#ffffff', relief='flat')
        self.filter_button.pack(side=LEFT, padx=12)

        button_frame = Frame(top_panel, bg='#232323')
        button_frame.pack(side=RIGHT, padx=30, pady=12)
        self.pause_button = Button(button_frame, text='Pause', font=('Segoe UI', 10, 'bold'), command=self.on_pause, bg='#006400', fg='#fafafa', activebackground='#a03c3c', activeforeground='#ffffff', relief='flat', width=10)
        self.pause_button.pack(side=LEFT, padx=5)
        self.clear_button = Button(button_frame, text='Clear', font=('Segoe UI', 10, 'bold'), command=self.on_clear, bg='#640000', fg='#fafafa', activebackground='#323232', activeforeground='#ffffff', relief='flat', width=10)
        self.clear_button.pack(side=LEFT, padx=5)

        main_panel = Frame(self.root, bg='#232323', bd=2, relief='groove')
        main_panel.pack(fill=BOTH, expand=True, padx=15, pady=10)

        columns = ("ID", 'PROTOCOL', "Src IP", 'Src Port', "Dst IP", 'Dst port',)
        self.packets_box = ttk.Treeview(main_panel, columns=columns, show='headings', selectmode='browse', height=20)
        self.packets_box.tag_configure('evenrow', background='#4b4b4b')
        self.packets_box.tag_configure('oddrow', background='#484848')
        style = ttk.Style()
        style.theme_use('clam')
        style.map("Treeview", background=[("selected", "#323232")])
        style.configure("Treeview", rowheight=25)
        style.layout("Treeview", [
            ('Treeview.field', {'sticky': 'nswe', 'children': [
                ('Treeview.padding', {'sticky': 'nswe', 'children': [
                    ('Treeview.treearea', {'sticky': 'nswe'})
                ]})
            ]})
        ])

        style.configure('Treeview.Heading', background='#232323', foreground='#fafafa', font=('Segoe UI', 10, 'bold'))
        for col in columns:
            self.packets_box.heading(col, text=col)
            self.packets_box.column(col, anchor=CENTER, width=120 if col!="Protocol" else 90)
        self.packets_box.pack(fill=BOTH, expand=TRUE, side=LEFT, padx=2, pady=2)

        scrollbar = Scrollbar(main_panel, command=self.packets_box.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.packets_box.configure(yscroll=scrollbar.set)

        self.packets_box.bind('<Double-1>', self.open_data)

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
        for item in self.packets_box.get_children():
            self.packets_box.delete(item)
        self.Sniffer.packets = []
        self.num_of_packets = 0

    def get_filter(self, event=None):
        self.filters = self.filter_entry.get().split()
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
        elif filter[index] in self.protocols:
            filter[index] = (packet['protocol'] == filter[index])
        elif filter[index] == '(':
            index2 = filter.index(')', index)
            print(index, index2, filter)
            filter[index:index2+1] = [self.check_filters(packet, filter[index+1:index2])]
        else:
            del(filter[index])

    def check_filters(self, packet, filter):
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
            else:
                self.check_filter(packet, filter, i)
            i += 1
        if len(filter) < 1:
            return True
        return filter[0]

    def filter_change(self):
        for item in self.packets_box.get_children():
            self.packets_box.delete(item)

        idx = 0
        for packet in self.Sniffer.get_packets():
            if self.check_filters(packet, self.filters.copy()):
                tag = 'evenrow' if (self.num_of_packets + idx) % 2 == 0 else 'oddrow'
                self.packets_box.insert('', 'end', values=self.packet_values(packet), tags=(tag,))
            idx += 1

        self.num_of_packets = len(self.Sniffer.get_packets())

    def update_packets(self):
        new_packets = self.Sniffer.get_packets()[self.num_of_packets:]

        idx = 0
        for packet in new_packets:
            if self.check_filters(packet, self.filters.copy()):
                tag = 'evenrow' if (self.num_of_packets + idx) % 2 == 0 else 'oddrow'
                self.packets_box.insert('', 'end', values=self.packet_values(packet), tags=(tag,))
            idx += 1

        self.num_of_packets += len(new_packets)

        if self.pause == 0:
            self.root.after(75, self.update_packets)

    def packet_values(self, packet):
        return (packet['id'], packet['protocol'], packet['src_ip'], packet['src_port'], packet['dst_ip'], packet['dst_port'])

    def open_data(self, event=None):
        # Get selected item from Treeview
        selected = self.packets_box.selection()
        if not selected:
            return
        index = int(self.packets_box.item(selected[0])["values"][0])
        packet = self.Sniffer.packets[index]

        # --- UI Window ---
        top = Toplevel(self.root)
        top.title(f"Packet #{index}")
        top.geometry("750x500")
        top.config(bg='#232323')

        # --- Title Label ---
        label = Label(top, text=f"Packet #{index} Data:", font=('Segoe UI', 12, 'bold'), bg='#232323', fg='#fafafa')
        label.pack(pady=(16, 8))

        # --- Navigation Buttons ---
        button_frame = Frame(top, bg='#232323')
        button_frame.pack(pady=8, padx=16)

        def next_packet():
            nonlocal index
            if index < len(self.Sniffer.packets) - 1:
                index += 1
                top.title(f"Packet #{index}")
                label.config(text=f"Packet #{index} Data:")
                render_details(index)
                pkt = self.Sniffer.packets[index]
                raw_data = pkt.get('data', b'')
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
                render_details(index)
                pkt = self.Sniffer.packets[index]
                raw_data = pkt.get('data', b'')
                if isinstance(raw_data, bytes):
                    formatted_data = ' '.join(f"{byte:02X}" for byte in raw_data)
                else:
                    formatted_data = str(raw_data)
                text.config(state="normal")
                text.delete("1.0", END)
                text.insert(END, formatted_data)
                text.config(state="disabled")

        next_button = Button(button_frame, text='Next', command=next_packet, bg='#232323', fg='#fafafa', font=('Segoe UI', 10, 'bold'), relief='flat', width=10)
        next_button.pack(side=RIGHT, padx=10)
        back_button = Button(button_frame, text='Back', command=back_packet, bg='#232323', fg='#fafafa', font=('Segoe UI', 10, 'bold'), relief='flat', width=10)
        back_button.pack(side=LEFT, padx=10)

        # --- Main Horizontal Split ---
        main_frame = Frame(top, bg='#232323')
        main_frame.pack(fill=BOTH, expand=True, padx=20, pady=8)

        # --- Left: Packet Details Table ---
        details_frame = Frame(main_frame, bg='#232323')
        details_frame.pack(side=LEFT, fill=Y, padx=(0,18), pady=4)

        details_fields = ['ID', 'Protocol', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port']
        details_labels = []

        for i, name in enumerate(details_fields):
            title_label = Label(details_frame, text=f"{name}:", font=('Segoe UI', 10, 'bold'), bg='#232323', fg='#fafafa', width=18, anchor='e', justify='right')
            title_label.grid(row=i, column=0, sticky='e', pady=3)
            value_label = Label(details_frame, text="", font=('Consolas', 10), bg='#232323', fg='#fafafa', width=22, anchor='w', justify='left')
            value_label.grid(row=i, column=1, sticky='w', pady=3)
            details_labels.append(value_label)

        def render_details(idx):
            pkt = self.Sniffer.packets[idx]
            fields = [
                pkt.get('id', ''),
                pkt.get('protocol', ''),
                pkt.get('src_ip', ''),
                pkt.get('src_port', ''),
                pkt.get('dst_ip', ''),
                pkt.get('dst_port', ''),
            ]
            for i, value_label in enumerate(details_labels):
                value_label.config(text=str(fields[i]))

        # --- Right: Hex Dump ---
        hex_frame = Frame(main_frame, bg='#232323')
        hex_frame.pack(side=RIGHT, fill=BOTH, expand=True)

        Label(hex_frame, text="Raw Data (hex):", font=('Segoe UI', 10, 'bold'), bg='#232323', fg='#fafafa').pack(anchor='w', padx=4, pady=(0,2))

        text_frame = Frame(hex_frame, bg='#232323')
        text_frame.pack(fill=BOTH, expand=True)

        scrollbar = Scrollbar(text_frame)
        scrollbar.pack(side=RIGHT, fill=Y)

        text = Text(
            text_frame,
            wrap="none",
            yscrollcommand=scrollbar.set,
            font=('Consolas', 13),
            bg='#000000',
            fg='#fafafa',
            height=16,  # bigger height
            width=44    # bigger width
        )
        text.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.config(command=text.yview)

        # --- Initial render ---
        render_details(index)
        raw_data = packet.get('data', b'')
        if isinstance(raw_data, bytes):
            formatted_data = ' '.join(f"{byte:02X}" for byte in raw_data)
        else:
            formatted_data = str(raw_data)
        text.insert(END, formatted_data)
        text.config(state="disabled")
