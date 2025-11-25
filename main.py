from filter import Filter
from sniffer import Sniffer
from UI import UI

def main():
    filter = Filter()
    sniffer = Sniffer()
    UI(sniffer, filter)

if __name__ == "__main__":
    main()
