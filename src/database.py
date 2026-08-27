"""
Database Module
Handles logging of packet analysis results to SQLite
"""

import sqlite3
import json
from datetime import datetime
import logging
import os

logger = logging.getLogger(__name__)

class DatabaseLogger:
    """Logs analysis results to SQLite database"""
    
    def __init__(self, db_path='packet_analysis.db'):
        """
        Initialize database connection
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._create_tables()
        logger.info(f"Database initialized: {db_path}")
    
    def _create_tables(self):
        """Create necessary tables if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create packets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                src_ip TEXT,
                dst_ip TEXT,
                protocol TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                packet_size INTEGER,
                valid BOOLEAN,
                findings TEXT
            )
        ''')
        
        # Create findings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                packet_id INTEGER,
                finding_type TEXT,
                severity TEXT,
                details TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(packet_id) REFERENCES packets(id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_packet(self, packet_info, validation_result):
        """
        Log a single packet and its validation results
        
        Args:
            packet_info: Dictionary with packet details
            validation_result: Dictionary with validation results
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Insert packet
        cursor.execute('''
            INSERT INTO packets 
            (src_ip, dst_ip, protocol, src_port, dst_port, packet_size, valid, findings)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            packet_info.get('src_ip'),
            packet_info.get('dst_ip'),
            packet_info.get('protocol'),
            packet_info.get('src_port'),
            packet_info.get('dst_port'),
            packet_info.get('size', 0),
            1 if validation_result.get('valid') else 0,
            json.dumps(validation_result.get('findings', []))
        ))
        
        packet_id = cursor.lastrowid
        
        # Log individual findings
        for finding in validation_result.get('findings', []):
            cursor.execute('''
                INSERT INTO findings (packet_id, finding_type, severity, details)
                VALUES (?, ?, ?, ?)
            ''', (
                packet_id,
                finding.get('type'),
                finding.get('severity'),
                finding.get('details')
            ))
        
        conn.commit()
        conn.close()
    
    def log_packets(self, parsed_packets, validation_results):
        """Log multiple packets and their results"""
        for packet_info, validation_result in zip(parsed_packets, validation_results):
            self.log_packet(packet_info, validation_result)
        logger.info(f"Logged {len(parsed_packets)} packets")
    
    def get_summary(self):
        """Get summary statistics from the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total packets
        cursor.execute("SELECT COUNT(*) FROM packets")
        total_packets = cursor.fetchone()[0]
        
        # Failed packets
        cursor.execute("SELECT COUNT(*) FROM packets WHERE valid = 0")
        failed_packets = cursor.fetchone()[0]
        
        # Findings count
        cursor.execute("SELECT COUNT(*) FROM findings")
        total_findings = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_packets': total_packets,
            'failed_packets': failed_packets,
            'success_rate': ((total_packets - failed_packets) / total_packets * 100) if total_packets > 0 else 0,
            'total_findings': total_findings
        }
    
    def get_recent_findings(self, limit=10):
        """Get most recent findings"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT f.finding_type, f.severity, f.details, f.timestamp,
                   p.src_ip, p.dst_ip
            FROM findings f
            JOIN packets p ON f.packet_id = p.id
            ORDER BY f.timestamp DESC
            LIMIT ?
        ''', (limit,))
        
        results = cursor.fetchall()
        conn.close()
        
        return [{
            'type': r[0],
            'severity': r[1],
            'details': r[2],
            'timestamp': r[3],
            'src_ip': r[4],
            'dst_ip': r[5]
        } for r in results]