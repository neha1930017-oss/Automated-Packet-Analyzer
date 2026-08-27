"""
Protocol Parser Module
Identifies and extracts protocol information from packets
"""

from scapy.all import Ether, IP, TCP, UDP, ICMP, ARP, DNS
import logging

logger = logging.getLogger(__name__)

class ProtocolParser:
    """Parses packets to identify protocols and extract information"""
    
    PROTOCOL_MAP = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP'
    }
    
    def __init__(self):
        self.parsed_packets = []
        logger.info("ProtocolParser initialized")
    
    def parse_packet(self, packet):
        """
        Parse a single packet and extract protocol information
        
        Returns:
            Dictionary with parsed information
        """
        parsed_info = {
            'protocols': [],
            'layer2': {},
            'layer3': {},
            'layer4': {},
            'application': {}
        }
        
        # Layer 2 (Ethernet)
        if Ether in packet:
            eth = packet[Ether]
            parsed_info['layer2'] = {
                'src_mac': eth.src,
                'dst_mac': eth.dst,
                'type': hex(eth.type)
            }
            parsed_info['protocols'].append('Ethernet')
        
        # Layer 3 (IP)
        if IP in packet:
            ip = packet[IP]
            parsed_info['layer3'] = {
                'src_ip': ip.src,
                'dst_ip': ip.dst,
                'ttl': ip.ttl,
                'proto': ip.proto,
                'proto_name': self.PROTOCOL_MAP.get(ip.proto, 'Unknown')
            }
            parsed_info['protocols'].append('IP')
            
        # Layer 4 (TCP/UDP)
        if TCP in packet:
            tcp = packet[TCP]
            parsed_info['layer4'] = {
                'sport': tcp.sport,
                'dport': tcp.dport,
                'flags': tcp.flags,
                'seq': tcp.seq,
                'ack': tcp.ack
            }
            parsed_info['protocols'].append('TCP')
            
        elif UDP in packet:
            udp = packet[UDP]
            parsed_info['layer4'] = {
                'sport': udp.sport,
                'dport': udp.dport,
                'len': udp.len
            }
            parsed_info['protocols'].append('UDP')
            
        # ICMP Protocol - CORRECT INDENTATION (same level as TCP/UDP)
        if ICMP in packet:
            icmp = packet[ICMP]
            parsed_info['layer3']['proto_name'] = 'ICMP'
            parsed_info['protocols'].append('ICMP')

        # Application Layer
        if DNS in packet:
            dns = packet[DNS]
            parsed_info['application'] = {
                'type': 'DNS',
                'qd_count': dns.qdcount,
                'an_count': dns.ancount
            }
            parsed_info['protocols'].append('DNS')
            
        # ARP
        if ARP in packet:
            arp = packet[ARP]
            parsed_info['application'] = {
                'type': 'ARP',
                'op': arp.op,
                'psrc': arp.psrc,
                'pdst': arp.pdst
            }
            parsed_info['protocols'].append('ARP')
            
        return parsed_info
    
    def parse_packets(self, packets):
        """Parse a list of packets"""
        self.parsed_packets = [self.parse_packet(pkt) for pkt in packets]
        return self.parsed_packets
    
    def get_protocol_stats(self):
        """Get statistics about protocol distribution"""
        stats = {}
        for parsed in self.parsed_packets:
            for proto in parsed['protocols']:
                stats[proto] = stats.get(proto, 0) + 1
        return stats