"""
Main Application Entry Point
Orchestrates the entire packet analysis workflow
"""

from packet_capture import PacketCapture
from protocol_parser import ProtocolParser
from validator import Validator
from database import DatabaseLogger
from report_generator import ReportGenerator
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def run_analysis(interface=None, packet_count=20, timeout=10):
    """
    Run complete packet analysis workflow
    
    Args:
        interface: Network interface name
        packet_count: Number of packets to capture
        timeout: Capture timeout in seconds
    """
    logger.info("🚀 Starting Packet Analysis Pipeline")
    
    # 1. Capture packets
    logger.info("📡 Capturing packets...")
    capturer = PacketCapture(interface)
    raw_packets = capturer.capture(count=packet_count, timeout=timeout)
    
    if not raw_packets:
        logger.warning("No packets captured. Exiting.")
        return
    
    # 2. Parse packets
    logger.info("🔍 Parsing packets...")
    parser = ProtocolParser()
    parsed_packets = parser.parse_packets(raw_packets)
    
    # Get protocol statistics
    proto_stats = parser.get_protocol_stats()
    logger.info(f"📊 Protocol distribution: {proto_stats}")
    
    # 3. Validate packets
    logger.info("✅ Validating packets...")
    validator = Validator()
    validation_results = []
    packet_summaries = []
    
    for raw_packet, parsed in zip(raw_packets, parsed_packets):
        # Run validations
        result = validator.validate_packet(raw_packet)
        validation_results.append(result)
        
        # Create packet summary for database
        summary = {
            'src_ip': parsed.get('layer3', {}).get('src_ip'),
            'dst_ip': parsed.get('layer3', {}).get('dst_ip'),
            'protocol': ', '.join(parsed.get('protocols', ['Unknown'])),
            'src_port': parsed.get('layer4', {}).get('sport'),
            'dst_port': parsed.get('layer4', {}).get('dport'),
            'size': len(raw_packet),
            'valid': result['valid'],
            'findings': result.get('findings', [])
        }
        packet_summaries.append(summary)
    
    # 4. Log to database
    logger.info("💾 Logging to database...")
    db = DatabaseLogger()
    db.log_packets(packet_summaries, validation_results)
    
    # 5. Generate summary
    summary_stats = db.get_summary()
    
    # 6. Generate reports
    logger.info("📊 Generating reports...")
    report_gen = ReportGenerator()
    
    # HTML Report
    html_file = report_gen.generate_html_report(
        findings=validator.get_findings(),
        summary=summary_stats,
        parsed_packets=packet_summaries
    )
    
    # JSON Report
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
    print(f"📄 Report: {html_file}")
    print(f"📄 JSON Report: {json_file}")
    print("="*50 + "\n")

if __name__ == "__main__":
    # Run with default settings
    run_analysis()
    
    # You can also specify parameters:
    # run_analysis(interface='eth0', packet_count=50, timeout=30)