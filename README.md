# Automated Network Packet Analyzer & Tester

An enterprise-grade, object-oriented Python framework designed to capture, parse, and validate real-time Layer 2 (Ethernet) and Layer 3/4 (IP/TCP/UDP) network traffic. 

## Core Architecture
*   **Decoupled Ingestion Engine (`NetworkPacketAnalyzer`):** Interfaces with low-level network drivers to parse hardware headers and nested packet payloads.
*   **Automated Validation Engine (`AutomatedValidationEngine`):** Applies deterministic rules to catch anomalies like frame size violations (MTUs), spoofed traffic, or scan flags.
*   **Structured Performance Logging (`DatabaseLogger`):** Commits raw network transactions into an optimized SQLite database for post-capture telemetry analysis.

## Core Tech Stack
*   **Language:** Python 3
*   **Networking Foundations:** Scapy, Core Sockets Architecture
*   **Database Management:** SQLite3
*   **Security Context:** High-Privilege Raw Socket Ingestion
