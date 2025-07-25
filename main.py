from sniffer import sniffer
from UI import UI

FILTERS = []

def main():
    running = True
    Window = UI()
    Sniffer = sniffer()

    while running:
        Sniffer.sniffing()
        if input('Continue running? ').lower() != 'y':
            running = False

if __name__ == "__main__":
    main()
