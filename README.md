# Automated Network Packet Analyzer & Tester

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

An enterprise-grade, object-oriented Python framework designed to capture, parse, and validate real-time network traffic with automated anomaly detection.

## ✨ Features

- **Real-time Packet Capture** - Capture live network traffic from any interface
- **Protocol Parsing** - Identify and parse Ethernet, IP, TCP, UDP, ICMP, DNS, and ARP
- **Automated Validation** - Detect MTU violations, suspicious flags, and anomalies
- **Database Logging** - Store all results in SQLite for analysis
- **Professional Reports** - Generate HTML and JSON reports with findings
- **Unit Tested** - Comprehensive test suite for reliability

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Administrator/root privileges (for packet capture)

### Installation

```bash
# Clone the repository
git clone https://github.com/neha1930017-oss/Automated-Packet-Analyzer.git
cd Automated-Packet-Analyzer

# Install dependencies
pip install -r requirements.txt