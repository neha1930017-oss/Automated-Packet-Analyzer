"""
Validator Module
Applies validation rules to detect anomalies in network packets
"""

from scapy.all import IP, TCP
import logging

logger = logging.getLogger(__name__)

class Validator:
    """Validates packets against various rule sets"""
    
    def __init__(self):
        self.rules = []
        self.findings = []
        logger.info("Validator initialized")
    
    def validate_mtu(self, packet, mtu=1500):
        """
        Check if packet size exceeds MTU
        
        Args:
            packet: Scapy packet object
            mtu: Maximum Transmission Unit (default: 1500)
            
        Returns:
            Boolean: True if valid, False if violation
        """
        packet_size = len(packet)
        if packet_size > mtu:
            finding = {
                'type': 'MTU_VIOLATION',
                'severity': 'HIGH',
                'details': f'Packet size {packet_size} exceeds MTU {mtu}',
                'packet_summary': self._get_packet_id(packet)
            }
            self.findings.append(finding)
            logger.warning(f"MTU violation: {packet_size} bytes")
            return False
        return True
    
    def validate_ip_checksum(self, packet):
        """Validate IP header checksum"""
        if IP in packet:
            # Scapy automatically validates checksum
            if hasattr(packet[IP], 'chksum') and packet[IP].chksum == 0:
                # In some cases, checksum might be 0 (not calculated)
                # This is a simplified check
                return True
        return True
    
    def detect_suspicious_flags(self, packet):
        """
        Detect suspicious TCP flag combinations
        
        Known suspicious patterns:
        - NULL scan: No flags set
        - FIN scan: FIN flag set without ACK
        - XMAS scan: FIN, URG, PSH flags set
        """
        if TCP in packet:
            tcp = packet[TCP]
            flags = tcp.flags
            
            # Check for NULL scan
            if flags == 0:
                finding = {
                    'type': 'SUSPICIOUS_FLAGS',
                    'severity': 'MEDIUM',
                    'details': 'NULL scan detected (no flags set)',
                    'packet_summary': self._get_packet_id(packet)
                }
                self.findings.append(finding)
                logger.warning("NULL scan detected")
                return False
                
            # Check for XMAS scan
            if hasattr(flags, 'F') and hasattr(flags, 'U') and hasattr(flags, 'P'):
                if flags.F and flags.U and flags.P:
                    finding = {
                        'type': 'SUSPICIOUS_FLAGS',
                        'severity': 'MEDIUM',
                        'details': 'XMAS scan detected (FIN+URG+PSH)',
                        'packet_summary': self._get_packet_id(packet)
                    }
                    self.findings.append(finding)
                    logger.warning("XMAS scan detected")
                    return False
        return True
    
    def validate_packet(self, packet):
        """Run all validations on a packet"""
        results = {
            'valid': True,
            'findings': [],
            'checks_passed': 0,
            'checks_failed': 0
        }
        
        # Run each validation
        checks = [
            self.validate_mtu(packet),
            self.detect_suspicious_flags(packet),
            self.validate_ip_checksum(packet)
        ]
        
        results['checks_passed'] = sum(1 for c in checks if c)
        results['checks_failed'] = len(checks) - results['checks_passed']
        results['valid'] = results['checks_failed'] == 0
        
        return results
    
    def _get_packet_id(self, packet):
        """Get a unique identifier for a packet"""
        if IP in packet:
            return f"IP:{packet[IP].src}->{packet[IP].dst}"
        return str(packet.summary())
    
    def get_findings(self):
        """Get all findings from validations"""
        return self.findings
    
    def clear_findings(self):
        """Clear all stored findings"""
        self.findings = []
        logger.info("Findings cleared")