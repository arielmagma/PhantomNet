from tkinter import *

class UI:
    def __init__(self):
        self.root = None
        self.title = None
        self.filter_entry = None
        self.packets = None

        self.setup_window()

    def setup_window(self):
        self.root = Tk()
        self.root.title('PhantomNet')
        self.root.geometry('750x400')
        self.setup_widgets()
        self.setup_packets()

        self.root.mainloop()

    def setup_widgets(self):
        self.title = Label(self.root, text='Welcome to PhantomNet')
        self.title.pack()

        Label(self.root, text = 'Filters: ').pack()
        self.filter_entry = Entry(self.root)
        self.filter_entry.pack()

    def setup_packets(self):
        scrollbar = Scrollbar(self.root)
        scrollbar.pack(side=LEFT, fill=Y)
        packets = Listbox(self.root, yscrollcommand=scrollbar.set)

        for line in range(100):
            packets.insert(END, 'This is line number' + str(line))

        packets.pack(side=LEFT, fill=BOTH)
        scrollbar.config(command=packets.yview)

if __name__ == '__main__':
    my_ui = ui()
