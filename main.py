from sniffer import sniffer
from UI import UI

FILTERS = []

def main():
    Sniffer = sniffer()
    Window = UI(Sniffer)

if __name__ == "__main__":
    main()
