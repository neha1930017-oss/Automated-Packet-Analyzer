"""
Unit tests for the Validator module
"""

import unittest
from scapy.all import Ether, IP, TCP
import sys
import os

# Add src directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from validator import Validator

class TestValidator(unittest.TestCase):
    """Test cases for Validator class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.validator = Validator()
    
    def test_mtu_validation_pass(self):
        """Test that standard packets pass MTU validation"""
        packet = Ether()/IP()/("x" * 1400)  # ~1500 bytes
        result = self.validator.validate_mtu(packet)
        self.assertTrue(result)
    
    def test_mtu_validation_fail(self):
        """Test that jumbo packets fail MTU validation"""
        packet = Ether()/IP()/("x" * 9000)  # 9000+ bytes
        result = self.validator.validate_mtu(packet)
        self.assertFalse(result)
        self.assertTrue(len(self.validator.get_findings()) > 0)
    
    def test_suspicious_flags_null_scan(self):
        """Test detection of NULL scan (no flags)"""
        packet = Ether()/IP()/TCP(flags=0)
        result = self.validator.detect_suspicious_flags(packet)
        self.assertFalse(result)
    
    def test_suspicious_flags_xmas_scan(self):
        """Test detection of XMAS scan (FIN+URG+PSH)"""
        packet = Ether()/IP()/TCP(flags='FUP')
        result = self.validator.detect_suspicious_flags(packet)
        self.assertFalse(result)
    
    def test_normal_packet_pass(self):
        """Test a normal packet passes all validations"""
        packet = Ether()/IP()/TCP(flags='A')
        result = self.validator.validate_packet(packet)
        self.assertTrue(result['valid'])
        self.assertEqual(result['checks_failed'], 0)
    
    def test_validator_clear_findings(self):
        """Test clearing findings"""
        packet = Ether()/IP()/("x" * 9000)
        self.validator.validate_mtu(packet)
        self.assertTrue(len(self.validator.get_findings()) > 0)
        self.validator.clear_findings()
        self.assertEqual(len(self.validator.get_findings()), 0)

if __name__ == '__main__':
    unittest.main()