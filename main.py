from Filter import Filter
from sniffer import sniffer
from UI import UI

def main():
    filter = Filter()
    Sniffer = sniffer()
    Window = UI(Sniffer, filter)

if __name__ == "__main__":
    main()
