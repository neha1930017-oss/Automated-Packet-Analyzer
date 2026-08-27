"""
Packet Capture Module
Handles real-time network packet sniffing using Scapy
"""

from scapy.all import sniff, Ether, IP, TCP, UDP
from scapy.layers.inet import IP
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PacketCapture:
    """Captures network packets from a specified interface"""
    
    def __init__(self, interface=None):
        """
        Initialize packet capture
        
        Args:
            interface: Network interface name (e.g., 'eth0', 'Wi-Fi')
                      If None, tries to auto-detect
        """
        self.interface = interface
        self.captured_packets = []
        logger.info(f"PacketCapture initialized on interface: {interface or 'default'}")
    
    def capture(self, count=10, timeout=10):
        """
        Capture network packets
        
        Args:
            count: Number of packets to capture
            timeout: Maximum time to wait in seconds
            
        Returns:
            List of captured packets
        """
        try:
            logger.info(f"Starting capture: {count} packets, {timeout}s timeout")
            
            # Sniff packets
            packets = sniff(
                iface=self.interface,
                count=count,
                timeout=timeout
            )
            
            self.captured_packets = packets
            logger.info(f"Captured {len(packets)} packets")
            return packets
            
        except PermissionError:
            logger.error("Permission denied. Run as administrator/root")
            return []
        except Exception as e:
            logger.error(f"Capture error: {e}")
            return []
    
    def get_packet_summary(self, packet):
        """Get a summary of a single packet"""
        summary = {
            'length': len(packet),
            'protocol': 'Unknown'
        }
        
        if Ether in packet:
            summary['src_mac'] = packet[Ether].src
            summary['dst_mac'] = packet[Ether].dst
            
        if IP in packet:
            summary['src_ip'] = packet[IP].src
            summary['dst_ip'] = packet[IP].dst
            summary['protocol'] = 'IP'
            
        if TCP in packet:
            summary['protocol'] = 'TCP'
            summary['src_port'] = packet[TCP].sport
            summary['dst_port'] = packet[TCP].dport
            
        if UDP in packet:
            summary['protocol'] = 'UDP'
            summary['src_port'] = packet[UDP].sport
            summary['dst_port'] = packet[UDP].dport
            
        return summary
    
    def get_all_summaries(self):
        """Get summaries for all captured packets"""
        return [self.get_packet_summary(pkt) for pkt in self.captured_packets]