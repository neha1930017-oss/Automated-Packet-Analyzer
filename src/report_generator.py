"""
Report Generator Module
Creates HTML and JSON reports from analysis results
"""

import json
from datetime import datetime
import os
import logging

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generates reports in HTML and JSON formats"""
    
    def __init__(self, output_dir='reports'):
        """
        Initialize report generator
        
        Args:
            output_dir: Directory to store reports
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"ReportGenerator initialized, output: {output_dir}")
    
    def generate_html_report(self, findings, summary, parsed_packets, filename=None):
        """
        Generate HTML report
        
        Args:
            findings: List of findings
            summary: Summary statistics
            parsed_packets: List of parsed packets
            filename: Output filename (optional)
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'packet_analysis_{timestamp}.html'
        
        filepath = os.path.join(self.output_dir, filename)
        
        html_content = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Packet Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                h1, h2, h3 {{ color: #333; }}
                .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
                .summary-card {{ background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }}
                .summary-card .number {{ font-size: 28px; font-weight: bold; color: #007bff; }}
                .summary-card .label {{ color: #666; margin-top: 5px; }}
                .finding {{ border-left: 4px solid #dc3545; padding: 10px; margin: 10px 0; background: #fff5f5; }}
                .finding.high {{ border-color: #dc3545; background: #fff5f5; }}
                .finding.medium {{ border-color: #ffc107; background: #fffbf0; }}
                .finding.low {{ border-color: #17a2b8; background: #f0f9ff; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #f8f9fa; }}
                .protocol-badge {{ display: inline-block; padding: 3px 8px; background: #007bff; color: white; border-radius: 12px; font-size: 12px; }}
                .timestamp {{ color: #666; font-size: 14px; }}
                .pass {{ color: #28a745; font-weight: bold; }}
                .fail {{ color: #dc3545; font-weight: bold; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Network Packet Analysis Report</h1>
                <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <h2>Summary</h2>
                <div class="summary">
                    <div class="summary-card">
                        <div class="number">{summary['total_packets']}</div>
                        <div class="label">Total Packets</div>
                    </div>
                    <div class="summary-card">
                        <div class="number">{summary['failed_packets']}</div>
                        <div class="label">Anomalies Found</div>
                    </div>
                    <div class="summary-card">
                        <div class="number">{summary['success_rate']:.1f}%</div>
                        <div class="label">Pass Rate</div>
                    </div>
                    <div class="summary-card">
                        <div class="number">{summary['total_findings']}</div>
                        <div class="label">Total Findings</div>
                    </div>
                </div>
                
                <h2>Findings Details</h2>
                {self._generate_findings_html(findings)}
                
                <h2>Packet Details</h2>
                {self._generate_packet_table_html(parsed_packets, len(parsed_packets))}
            </div>
        </body>
        </html>
        '''
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {filepath}")
        return filepath
    
    def _generate_findings_html(self, findings):
        """Generate HTML for findings section"""
        if not findings:
            return '<p>[OK] No findings detected. All packets passed validation.</p>'
        
        html = ''
        for finding in findings:
            severity_class = finding.get('severity', 'low').lower()
            html += f'''
            <div class="finding {severity_class}">
                <strong>{finding.get('type', 'Unknown')}</strong> 
                <span class="protocol-badge">{finding.get('severity', 'LOW')}</span>
                <p>{finding.get('details', '')}</p>
                <span style="color: #666; font-size: 12px;">Packet: {finding.get('packet_summary', 'N/A')}</span>
            </div>
            '''
        return html
    
    def _generate_packet_table_html(self, packets, limit=20):
        """Generate HTML table for packet details"""
        if not packets:
            return '<p>No packets captured.</p>'
        
        html = '''
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Protocol</th>
                    <th>Size</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
        '''
        
        for i, packet in enumerate(packets[:limit], 1):
            status = '<span class="pass">[PASS]</span>' if packet.get('valid', True) else '<span class="fail">[FAIL]</span>'
            html += f'''
            <tr>
                <td>{i}</td>
                <td>{packet.get('src_ip', 'N/A')}</td>
                <td>{packet.get('dst_ip', 'N/A')}</td>
                <td><span class="protocol-badge">{packet.get('protocol', 'Unknown')}</span></td>
                <td>{packet.get('size', 0)} bytes</td>
                <td>{status}</td>
            </tr>
            '''
        
        html += '</tbody></table>'
        if len(packets) > limit:
            html += f'<p>Showing first {limit} of {len(packets)} packets</p>'
        
        return html
    
    def generate_json_report(self, findings, summary, parsed_packets, filename=None):
        """Generate JSON report"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'packet_analysis_{timestamp}.json'
        
        filepath = os.path.join(self.output_dir, filename)
        
        report_data = {
            'generated_at': datetime.now().isoformat(),
            'summary': summary,
            'findings': findings,
            'packets': [
                {
                    'src_ip': p.get('src_ip'),
                    'dst_ip': p.get('dst_ip'),
                    'protocol': p.get('protocol'),
                    'size': p.get('size'),
                    'valid': p.get('valid', True),
                    'findings': p.get('findings', [])
                }
                for p in parsed_packets
            ]
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"JSON report generated: {filepath}")
        return filepath