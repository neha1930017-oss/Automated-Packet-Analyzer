import os
import sys
import sqlite3
from datetime import datetime
from scapy.all import sniff, Ether, IP, TCP, UDP, conf

class DatabaseLogger:
    """Manages SQLite database storage for network packet logs and metrics."""
    def __init__(self, db_name="network_traffic.db"):
        self.db_name = db_name
        self.init_database()

    def init_database(self):
        try:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS packet_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        src_mac TEXT,
                        dst_mac TEXT,
                        src_ip TEXT,
                        dst_ip TEXT,
                        protocol TEXT,
                        packet_size INTEGER,
                        is_valid INTEGER,
                        anomaly_notes TEXT
                    )
                """)
                conn.commit()
        except sqlite3.Error as e:
            print(f"[-] Database initialization error: {e}")

    def log_packet(self, data):
        try:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO packet_logs 
                    (timestamp, src_mac, dst_mac, src_ip, dst_ip, protocol, packet_size, is_valid, anomaly_notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, data)
                conn.commit()
        except sqlite3.Error as e:
            print(f"[-] Database logging error: {e}")


class AutomatedValidationEngine:
    """Automates rules testing to check packet integrity and highlight anomalies."""
    @staticmethod
    def validate_packet(packet_info):
        is_valid = 1
        anomalies = []

        # Rule 1: Check Layer 2 MTU boundaries
        if packet_info['packet_size'] > 1518:
            is_valid = 0
            anomalies.append("Giant Frame (>1518 bytes)")
        elif packet_info['packet_size'] < 64:
            is_valid = 0
            anomalies.append("Runt Frame (<64 bytes)")

        # Rule 2: Loopback routing check
        if packet_info['src_ip'] == "127.0.0.1" and packet_info['dst_ip'] != "127.0.0.1":
            is_valid = 0
            anomalies.append("Suspicious Localhost Outbound")

        # Rule 3: Missing TCP Flags check
        if packet_info['protocol'] == "TCP" and packet_info['flags'] == 0:
            is_valid = 0
            anomalies.append("Null TCP Flags Scan")

        notes = ", ".join(anomalies) if anomalies else "Normal Traffic"
        return is_valid, notes


class NetworkPacketAnalyzer:
    """Captures network traffic and orchestrates parsing, testing, and logging."""
    def __init__(self, interface=None):
        self.interface = interface
        self.logger = DatabaseLogger()
        self.packet_count = 0

    def parse_packet(self, packet):
        packet_info = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'src_mac': 'N/A', 'dst_mac': 'N/A',
            'src_ip': 'N/A', 'dst_ip': 'N/A',
            'protocol': 'Unknown', 'packet_size': len(packet),
            'flags': None
        }

        # 1. Parse Layer 2 (Ethernet)
        if packet.haslayer(Ether):
            packet_info['src_mac'] = packet[Ether].src
            packet_info['dst_mac'] = packet[Ether].dst
            packet_info['protocol'] = 'Ethernet'

        # 2. Parse Layer 3 (IP)
        if packet.haslayer(IP):
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            packet_info['protocol'] = 'IP'

            # 3. Parse Layer 4 Protocols
            if packet.haslayer(TCP):
                packet_info['protocol'] = 'TCP'
                packet_info['flags'] = int(packet[TCP].flags)
            elif packet.haslayer(UDP):
                packet_info['protocol'] = 'UDP'

        is_valid, anomaly_notes = AutomatedValidationEngine.validate_packet(packet_info)

        log_data = (
            packet_info['timestamp'], packet_info['src_mac'], packet_info['dst_mac'],
            packet_info['src_ip'], packet_info['dst_ip'], packet_info['protocol'],
            packet_info['packet_size'], is_valid, anomaly_notes
        )

        self.logger.log_packet(log_data)
        self.packet_count += 1

        status = "[OK]" if is_valid else f"[ALERT: {anomaly_notes}]"
        print(f"[{packet_info['timestamp']}] Pkt #{self.packet_count} | {packet_info['protocol']} | "
              f"Size: {packet_info['packet_size']}B | {packet_info['src_ip']} -> {packet_info['dst_ip']} {status}")

    def start_sniffing(self, count=30):
        print(f"\n[+] Launching Packet Analyzer on interface: {self.interface or 'Default'}")
        print(f"[+] Capturing {count} packets... Live log output below:")
        print("-" * 90)
        
        try:
            sniff(iface=self.interface, prn=self.parse_packet, count=count, store=False)
        except Exception as e:
            print(f"[-] Sniffing Error on selected interface: {e}")
            print("[*] Tip: Try running the script again and picking a different index number.")
            return
        
        print("-" * 90)
        print(f"[+] Sniffing session complete. Total captured: {self.packet_count}")
        print(f"[+] All structured metrics stored securely in '{self.logger.db_name}'.")


if __name__ == "__main__":
    if os.name != 'nt' and os.geteuid() != 0:
        print("[-] Execution Error: This script requires root/administrator privileges.")
        sys.exit(1)

    print("[*] Available Network Interfaces:")
    
    interfaces = list(conf.ifaces.values())
    
    for idx, iface in enumerate(interfaces):
        print(f"  [{idx}] Name: {iface.name} | Description: {iface.description}")

    try:
        choice = int(input("\nEnter the index number of your active Wi-Fi interface: "))
        selected_interface = interfaces[choice].name
    except (ValueError, IndexError):
        print("[-] Invalid selection. Using default interface configuration.")
        selected_interface = None

    analyzer = NetworkPacketAnalyzer(interface=selected_interface)
    analyzer.start_sniffing(count=30)
