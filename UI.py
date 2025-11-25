from threading import Thread
from tkinter import *
from tkinter import ttk
from file_handler import save_session, load_session
from packet_handler import get_packet_data, hex_dump, find_tcp_conv
from ToggleFrame import ToggledFrame
from queue import Queue

class UI:
    def __init__(self, Sniffer, Filter):
        self.root = None
        self.filter = Filter
        self.Sniffer = Sniffer
        self.statistics = {'packets': 0}
        self.pause = False

        self.num_of_packets = 0
        self.queue = Queue()
        self.Sniffer.set_queue(self.queue)

        # start sniffer thread once
        self.Sniffer.start(daemon=True)

        self.setup_window()

    def setup_window(self):
        self.root = Tk()
        self.root.title('PhantomNet')
        self.root.geometry('950x500')
        self.root.config(bg='#000000')
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.menu_bar = Menu(self.root, bg='#232323', fg='#fafafa', relief='flat')
        file_menu = Menu(self.menu_bar, tearoff=0, bg='#232323', fg='#fafafa')
        file_menu.add_command(label='Exit', command=self.on_close)
        file_menu.add_command(label='Save', command=self.save)
        file_menu.add_command(label='Load', command=self.load)
        self.menu_bar.add_cascade(label='File', menu=file_menu)
        help_menu = Menu(self.menu_bar, tearoff=0, bg='#232323', fg='#fafafa')
        help_menu.add_command(label='About', command=self.show_about)
        self.menu_bar.add_cascade(label='Help', menu=help_menu)
        stats_menu = Menu(self.menu_bar, tearoff=0, bg='#232323', fg='#fafafa')
        stats_menu.add_command(label='Stats', command=self.open_statistics)
        self.menu_bar.add_cascade(label='Stats', menu=stats_menu)
        self.root.config(menu=self.menu_bar)

        self.setup_widgets()

        # start periodic UI consumer
        self.root.after(75, self.update_packets)
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

        self.packets_box.tag_configure('evenrow', background='#2b2b2b')
        self.packets_box.tag_configure('oddrow', background='#282828')
        style = ttk.Style()
        style.theme_use('clam')
        style.map("Treeview", background=[("selected", "#2f2f2f")])
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
            # keep reasonable widths
            self.packets_box.column(col, anchor=CENTER, width=120 if col != "Protocol" else 90)
        self.packets_box.pack(fill=BOTH, expand=TRUE, side=LEFT, padx=2, pady=2)

        scrollbar = Scrollbar(main_panel, command=self.packets_box.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.packets_box.configure(yscroll=scrollbar.set)

        self.packets_box.bind('<Double-1>', self.open_data)
        # safer right-click: check selection first
        self.packets_box.bind('<Button-3>', self._on_right_click)

    def _on_right_click(self, event):
        sel = self.packets_box.selection()
        if not sel:
            return
        try:
            idx = int(self.packets_box.item(sel[0], "values")[0])
            find_tcp_conv(self.Sniffer.get_packets(), idx)
        except Exception:
            return

    def on_close(self):
        # pause UI updates and signal sniffer to stop
        self.pause = True
        self.Sniffer.pause = True
        self.Sniffer.stop()
        self.root.destroy()

    def on_pause(self):
        # toggle pause without restarting threads
        self.pause = not self.pause
        self.Sniffer.pause = self.pause
        # update button color to show state
        self.pause_button.config(bg='#640000' if self.pause else '#006400')

    def on_clear(self):
        for item in self.packets_box.get_children():
            self.packets_box.delete(item)
        self.Sniffer.set_packets([])
        # clear stats and counters
        self.num_of_packets = 0
        self.statistics = {'packets': 0}

    def get_filter(self, event=None):
        self.on_pause()
        self.filter.update_filter(self.filter_entry.get())
        self.filter_change()
        self.on_pause()

    def filter_change(self):
        # re-populate visible rows from Sniffer packets (safe copy)
        for item in self.packets_box.get_children():
            self.packets_box.delete(item)

        packets = self.Sniffer.get_packets()
        idx = 0
        for packet in packets:
            if self.filter.check_filters(packet):
                tag = 'evenrow' if (idx % 2) == 0 else 'oddrow'
                self.packets_box.insert('', 'end', values=self.packet_values(packet), tags=(tag,))
            idx += 1

        self.num_of_packets = len(packets)

    def update_packets(self):
        # consume all queued packets and update UI (only main thread)
        consumed = 0
        while not self.queue.empty():
            try:
                packet = self.queue.get_nowait()
            except Exception:
                break

            consumed += 1
            if self.filter.check_filters(packet):
                tag = 'evenrow' if (self.num_of_packets % 2) == 0 else 'oddrow'
                self.packets_box.insert('', 'end', values=self.packet_values(packet), tags=(tag,))

            # stats
            proto = packet.get('protocol', 'UNKNOWN')
            self.statistics[proto] = self.statistics.get(proto, 0) + 1
            self.statistics['packets'] = self.statistics.get('packets', 0) + 1

            self.num_of_packets += 1

        # schedule next poll (only if not paused)
        if not self.pause:
            self.root.after(75, self.update_packets)
        else:
            # still schedule occasionally to remain responsive to unpause/close
            self.root.after(250, self.update_packets)

    def packet_values(self, packet):
        src_ip, dst_ip, src_port, dst_port, protocol = get_packet_data(packet['Data'])
        return packet['id'], protocol, src_ip, src_port, dst_ip, dst_port

    def open_data(self, event=None):
        selected = self.packets_box.selection()
        if not selected:
            return
        index = int(self.packets_box.item(selected[0])["values"][0])
        packet = None
        # get a safe copy from sniffer
        packets = self.Sniffer.get_packets()
        if 0 <= index < len(packets):
            packet = packets[index]
        if packet is None:
            return

        top = Toplevel(self.root)
        top.title(f"Packet #{index}")
        top.geometry("800x550")
        top.config(bg='#232323')

        label = Label(top, text=f"Packet #{index} Data:", font=('Segoe UI', 12, 'bold'), bg='#232323', fg='#fafafa')
        label.pack(pady=(16, 8))

        button_frame = Frame(top, bg='#232323')
        button_frame.pack(pady=8, padx=16)

        def show_packet_at(new_index):
            nonlocal index, packet
            index = new_index
            if not (0 <= index < len(self.Sniffer.get_packets())):
                return
            packet = self.Sniffer.get_packets()[index]
            top.title(f"Packet #{index}")
            label.config(text=f"Packet #{index} Data:")
            data = hex_dump(packet['Hex'])
            text.config(state="normal")
            text.delete("1.0", END)
            text.insert(END, data)
            text.config(state="disabled")

            for toggleFrame in details_frame.winfo_children():
                toggleFrame.destroy()

            layer_data = packet['Data']
            for layer in packet['protocol layers']:
                ToggledFrame(details_frame, layer, layer_data).pack()
                if 'Data' in layer_data:
                    layer_data = layer_data['Data']

        def next_packet():
            show_packet_at(index + 1)

        def back_packet():
            show_packet_at(index - 1)

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

        layer_data = packet['Data']
        for layer in packet['protocol layers']:
            ToggledFrame(details_frame, layer, layer_data).pack()
            if 'Data' in layer_data:
                layer_data = layer_data['Data']

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
            yscrollcommand=scrollbar.set,
            font=('Consolas', 13),
            bg='#000000',
            fg='#fafafa',
            height=16,
            width=44,
            wrap=WORD
        )
        text.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.config(command=text.yview)

        raw_data = hex_dump(packet['Hex'])
        text.insert(END, raw_data)
        text.config(state="disabled")

    def show_about(self):
        pass

    def open_statistics(self):
        top = Toplevel(self.root)
        for protocol in self.statistics.keys():
            Label(top, text=f'{protocol}: {self.statistics[protocol]}').pack()

    def save(self):
        save_session(self.Sniffer.get_packets())

    def load(self):
        self.on_clear()
        self.Sniffer.set_packets(load_session())
        # repopulate UI
        self.filter_change()
