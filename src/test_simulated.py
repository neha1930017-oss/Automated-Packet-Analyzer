"""
Test the analyzer with simulated packets
"""

from scapy.all import Ether, IP, TCP, UDP, ICMP
from packet_capture import PacketCapture
from protocol_parser import ProtocolParser
from validator import Validator
from database import DatabaseLogger
from report_generator import ReportGenerator
import os

# Create simulated packets
print("📦 Creating simulated packets...")
packets = [
    Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=80, dport=443, flags='A'),  # Normal TCP
    Ether()/IP(src="192.168.1.3", dst="192.168.1.4")/UDP(sport=53, dport=12345),           # Normal UDP
    Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/("x" * 9000),                               # MTU Violation
    Ether()/IP(src="192.168.1.5", dst="192.168.1.6")/TCP(flags=0),                         # NULL scan
    Ether()/IP(src="192.168.1.7", dst="192.168.1.8")/TCP(flags='FUP'),                     # XMAS scan
    Ether()/IP(src="192.168.1.9", dst="192.168.1.10")/ICMP(),                              # ICMP packet
]

print(f"✅ Created {len(packets)} simulated packets")

# Parse packets
print("🔍 Parsing packets...")
parser = ProtocolParser()
parsed_packets = parser.parse_packets(packets)

# Show protocol stats
stats = parser.get_protocol_stats()
print(f"📊 Protocol Stats: {stats}")

# Validate packets
print("✅ Validating packets...")
validator = Validator()
validation_results = []
packet_summaries = []

for raw_packet, parsed in zip(packets, parsed_packets):
    result = validator.validate_packet(raw_packet)
    validation_results.append(result)
    
    summary = {
        'src_ip': parsed.get('layer3', {}).get('src_ip', 'N/A'),
        'dst_ip': parsed.get('layer3', {}).get('dst_ip', 'N/A'),
        'protocol': ', '.join(parsed.get('protocols', ['Unknown'])),
        'src_port': parsed.get('layer4', {}).get('sport', 0),
        'dst_port': parsed.get('layer4', {}).get('dport', 0),
        'size': len(raw_packet),
        'valid': result['valid'],
        'findings': result.get('findings', [])
    }
    packet_summaries.append(summary)

# Log to database
print("💾 Logging to database...")
db = DatabaseLogger('test_analysis.db')
db.log_packets(packet_summaries, validation_results)

# Generate summary
summary_stats = db.get_summary()

# Generate reports
print("📊 Generating reports...")
# Save to reports folder in project root
import os
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
reports_dir = os.path.join(project_root, 'reports')
os.makedirs(reports_dir, exist_ok=True)
report_gen = ReportGenerator(reports_dir)
html_file = report_gen.generate_html_report(
    findings=validator.get_findings(),
    summary=summary_stats,
    parsed_packets=packet_summaries
)

json_file = report_gen.generate_json_report(
    findings=validator.get_findings(),
    summary=summary_stats,
    parsed_packets=packet_summaries
)

# Print summary
print("\n" + "="*50)
print("📊 ANALYSIS COMPLETE")
print("="*50)
print(f"📝 Total Packets: {summary_stats['total_packets']}")
print(f"⚠️  Anomalies Found: {summary_stats['failed_packets']}")
print(f"✅ Pass Rate: {summary_stats['success_rate']:.1f}%")
print(f"📄 HTML Report: {html_file}")
print(f"📄 JSON Report: {json_file}")
print("="*50 + "\n")

# Show findings
if validator.get_findings():
    print("🚨 Findings Detected:")
    for i, finding in enumerate(validator.get_findings(), 1):
        print(f"  {i}. {finding['type']} - {finding['severity']}")
        print(f"     {finding['details']}")
else:
    print("✅ No findings detected!")