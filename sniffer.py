from scapy.all import sniff
from decoder import get_first_layer, decode
from packet_handler import get_protocol
from queue import Queue
import threading

class Sniffer:
    def __init__(self):
        self.packets = []
        self.packets_lock = threading.Lock()
        self.pause = False
        self.queue = Queue()
        self.stop_event = threading.Event()
        self._thread = None

    def set_queue(self, q: Queue):
        self.queue = q

    def start(self, daemon=True):
        if self._thread is None or not self._thread.is_alive():
            self.stop_event.clear()
            self._thread = threading.Thread(target=self.sniffing, daemon=daemon)
            self._thread.start()

    def stop(self):
        # signal sniff to stop and wait for thread to finish
        self.stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)

    def sniffing(self):
        # stop_filter returns True when stop_event is set
        sniff(prn=self.process_packet, store=False, stop_filter=lambda pkt: self.stop_event.is_set())

    def process_packet(self, packet):
        # Ignore packets when paused
        if self.pause:
            return

        try:
            hex_data = self.bytes_to_hex(bytes(packet))
            protocol = get_first_layer(hex_data)
            data = decode(hex_data, protocol)
            protocol_name, layers = get_protocol(data, protocol)

            with self.packets_lock:
                pkt_id = len(self.packets)
                pkt = {
                    'id': pkt_id,
                    'protocol': protocol_name,
                    'protocol layers': layers,
                    'Data': data,
                    'Hex': hex_data
                }
                self.packets.append(pkt)

            # deliver to UI via queue (non-blocking)
            if self.queue is not None:
                try:
                    self.queue.put_nowait(pkt)
                except Exception:
                    # if queue is full / unavailable, silently drop; UI will still have packets list
                    pass
        except Exception:
            # Keep sniffer resilient; don't let an exception kill the sniffer
            return

    def bytes_to_hex(self, data: bytes):
        return data.hex().upper()

    def get_packets(self):
        with self.packets_lock:
            # return a shallow copy to avoid caller mutating shared list
            return list(self.packets)

    def set_packets(self, packets):
        with self.packets_lock:
            self.packets = list(packets)
