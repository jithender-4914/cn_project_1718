import threading
import time
from datetime import datetime
from typing import Dict, List
import pandas as pd
from scapy.all import sniff, IP
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PacketProcessor:
    """Process and analyze network packets"""
    
    def __init__(self):
        self.protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        self.packet_data: List[Dict[str, any]] = []
        self.start_time: datetime = datetime.now()
        self.packet_count: int = 0
        self.lock: threading.Lock = threading.Lock()
        self.running: bool = True

    def start_capture(self) -> None:
        """Start a thread to capture packets"""
        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.start()

    def stop_capture(self) -> None:
        """Stop the packet capturing thread"""
        self.running = False
        self.capture_thread.join()

    def capture_packets(self) -> None:
        """Capture packets using scapy"""
        sniff(prn=self.process_packet, stop_filter=lambda x: not self.running)

    def process_packet(self, packet) -> None:
        """Process a captured packet"""
        try:
            if IP in packet:
                with self.lock:
                    self._add_packet_data(packet)
        except Exception as e:
            logger.error(f'Error processing packet: {str(e)}', exc_info=True)

    def _add_packet_data(self, packet) -> None:
        """Add packet data to the list"""
        timestamp = time.time()
        source = packet[IP].src
        destination = packet[IP].dst
        protocol = packet[IP].proto
        size = len(packet)
        self.packet_data.append({
            'timestamp': timestamp,
            'source': source,
            'destination': destination,
            'protocol': self.protocol_map.get(protocol, str(protocol)),
            'size': size
        })
        if len(self.packet_data) > 10000:
            self.packet_data.pop(0)

    def get_dataframe(self) -> pd.DataFrame:
        """Convert packet data to pandas DataFrame"""
        with self.lock:
            return pd.DataFrame(self.packet_data)