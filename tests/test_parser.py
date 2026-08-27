"""
Unit tests for the ProtocolParser module
"""

import unittest
from scapy.all import Ether, IP, TCP, UDP, ICMP, DNS
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from protocol_parser import ProtocolParser

class TestProtocolParser(unittest.TestCase):
    """Test cases for ProtocolParser class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.parser = ProtocolParser()
    
    def test_parse_tcp_packet(self):
        """Test parsing a TCP packet"""
        packet = Ether(src='00:11:22:33:44:55', dst='66:77:88:99:aa:bb') / \
                 IP(src='192.168.1.1', dst='192.168.1.2') / \
                 TCP(sport=80, dport=443, flags='A')
        
        result = self.parser.parse_packet(packet)
        
        self.assertIn('Ethernet', result['protocols'])
        self.assertIn('IP', result['protocols'])
        self.assertIn('TCP', result['protocols'])
        self.assertEqual(result['layer2']['src_mac'], '00:11:22:33:44:55')
        self.assertEqual(result['layer3']['src_ip'], '192.168.1.1')
        self.assertEqual(result['layer4']['sport'], 80)
        self.assertEqual(result['layer4']['dport'], 443)
    
    def test_parse_udp_packet(self):
        """Test parsing a UDP packet"""
        packet = Ether() / IP() / UDP(sport=53, dport=12345)
        
        result = self.parser.parse_packet(packet)
        self.assertIn('UDP', result['protocols'])
        self.assertEqual(result['layer4']['sport'], 53)
    
    def test_protocol_stats(self):
        """Test protocol statistics calculation"""
        test_packets = [
            Ether()/IP()/TCP(),
            Ether()/IP()/UDP(),
            Ether()/IP()/TCP(),
            Ether()/IP()/ICMP()
        ]
        
        self.parser.parse_packets(test_packets)
        stats = self.parser.get_protocol_stats()
        
        self.assertEqual(stats.get('TCP'), 2)
        self.assertEqual(stats.get('UDP'), 1)
        self.assertEqual(stats.get('ICMP'), 1)

if __name__ == '__main__':
    unittest.main()