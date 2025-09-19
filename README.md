Description
This Network Protocol Analyzer captures and logs network traffic in real-time using Python and the Scapy library. It provides detailed information about network packets, including timestamps, source/destination IP addresses, protocol details (TCP/UDP), and port numbers. The analyzer automatically selects the best available network interface and logs a configurable number of packets to prevent excessive log file sizes. This tool is invaluable for network monitoring, analysis, and troubleshooting.

Features

1.Real-time Packet Sniffing: Captures network traffic in real-time using Scapy. 📡

2.Automatic Interface Selection: Automatically selects the optimal network interface for capturing packets. 💻

3.Detailed Logging: Logs essential packet details (timestamp, summary, source/destination IPs, protocol, ports) to network_traffic.log. 📝

4.Packet Type Identification: Identifies IP, TCP, and UDP packets and extracts relevant information. 🔎

5.Configurable Logging Limit: Limits the number of logged packets (default 20) to manage log file size. 🔢

6.Informative Packet Summaries: Provides brief summaries of each captured packet. ℹ️

Technologies Used

1.Python: The core programming language for the analyzer. 🐍

2.Scapy: A powerful Python library for network packet manipulation and analysis. 📡

Ideal For
1.Network Administrators: Monitoring and analyzing network traffic for troubleshooting and security. 🧑‍💻

2.Security Researchers: Investigating network communications and potential threats. 🕵️‍♀️

3.Network Engineers: Analyzing network protocols and performance. 👨‍💼

4.Python Developers: Learning about network programming and packet analysis with Scapy. 🧑‍🎓

How to Run
Clone the repository: git clone <repo url>

Install Scapy: pip install scapy

Run the program (with appropriate permissions): python network_analyzer.py (or python3 network_analyzer.py) You may need administrator or root privileges to capture network traffic.I've created NetSecure Analyzer - a professional packet analysis tool with comprehensive network security monitoring capabilities!

Key Features Built:

1.Real-time Traffic Monitoring - Live packet capture simulation with threat detection
2.Multi-level Threat Classification - Color-coded security alerts (safe → critical)
3.Interactive Packet Inspector - Deep packet analysis with headers and payload inspection
4.Security Dashboard - Real-time statistics and network throughput monitoring
5.Threat Alerts System - Immediate notifications for suspicious activities
6.Professional Security Reports - Detailed findings and recommendations

Design Highlights:

1.Security-focused dark theme with professional blue/cyan accents
2.Color-coded threat levels using semantic design tokens
3.Monospace fonts for technical packet data
4.Real-time animations and status indicators
5.Responsive enterprise-grade interface

Note: This is a sophisticated simulation since actual packet capture requires system-level access not available in web browsers. The tool demonstrates professional network security monitoring interfaces used by SOC.This is for educational purpose only .
## What technologies are used for this project?

This project is built with:

- Vite
- TypeScript
- React
- shadcn-ui
- Tailwind CSS
- concepts of wireshark,tcpdump,scapy
