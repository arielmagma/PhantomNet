from threading import *
from time import *
from tkinter import *

class UI:
    def __init__(self, Sniffer):
        self.root = None
        self.title = None
        self.filter_entry = None
        self.packets_box = None

        self.Sniffer = Sniffer
        self.filters = []
        self.pause = 0

        self.sniffing_thread = Thread(target=self.Sniffer.sniffing).start()

        self.setup_window()

    def setup_window(self):
        self.root = Tk()
        self.root.title('PhantomNet')
        self.root.geometry('750x400')
        self.setup_widgets()

        self.root.after(100, self.update_packets)
        self.root.mainloop()

    def setup_widgets(self):
        self.title = Label(self.root, text='Welcome to PhantomNet')
        self.title.pack()

        Label(self.root, text = 'Filters: ').pack()
        self.filter_entry = Entry(self.root)
        self.filter_entry.pack()

        self.pause_checkbox = Checkbutton(self.root, text='Pause sniffing', variable=self.pause, command=self.on_pause).pack()
        scrollbar = Scrollbar(self.root)
        scrollbar.pack(side=LEFT, fill=Y)
        self.packets_box = Listbox(self.root, yscrollcommand=scrollbar.set, height = 50, width = 125)

        self.packets_box.pack(side=LEFT, fill=BOTH)
        scrollbar.config(command=self.packets_box.yview)

    def on_pause(self):
        print((self.pause + 1) % 2)
        if self.pause == 0:
            self.pause = 1
            print('Paused sniffing')
        else:
            self.pause = 0
            self.update_packets()

    def update_packets(self):
        lines = self.packets_box.size()
        new_packets = self.Sniffer.get_packets()[lines:]

        for packet in new_packets:
            self.packets_box.insert(END, f"{packet['id']}  |  {packet['protocol']}  |  {packet['src_ip']}  |  {packet['src_port']}  |  {packet['dst_ip']}  |  {packet['dst_port']}")

        if self.pause == 0:
            self.root.after(100, self.update_packets)
