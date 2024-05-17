# Network-Traffic-Analyzer-and-Firewall
The exponent necessitates network traffic due to IoT, cloud computing, and
mobile applications necessitate advanced network monitoring and security
measures. This paper introduces a network traffic analyzer that monitors, detects,
and mitigates suspicious activities by leveraging Wireshark's `tshark` for packet
analysis. The system identifies anomalies based on traffic patterns and implements
firewall rules using `iptables` to block malicious IP addresses. By integrating a
configurable threshold and a whitelist of trusted IPs, it effectively reduces false
positives and enhances network security. This research demonstrates the tool's
ability to provide real-time insights and proactive defense, significantly improving
network security management
Overview:

This repository contains a network traffic analyzer script that integrates with Wireshark and automates firewall rule implementation based on traffic analysis. The script is designed to enhance network security by monitoring incoming and outgoing traffic, detecting anomalies, and dynamically enforcing firewall rules to mitigate potential threats.


Features:

Traffic Analysis: Utilizes Wireshark's command-line utility tshark to analyze packet-level data, providing insights into network activity, including HTTP and HTTPS traffic.

Anomaly Detection: Identifies suspicious traffic patterns by setting configurable thresholds and comparing traffic metrics against whitelisted IP addresses.

Automated Firewall Rule Implementation: Implements firewall rules using iptables to block suspicious IP addresses detected during traffic analysis.

Whitelist Support: Allows users to define a whitelist of trusted IP addresses to prevent false positives and ensure uninterrupted network access for legitimate traffic.


Requirements:

Linux-based operating system

Wireshark installed (for packet capture)

Root or sudo privileges for firewall rule implementation


Usage:

Capture network traffic using Wireshark and save the pcap file.

Clone this repository or download the script (traffic_analyzer.sh).

Execute the script with the path to the pcap file as an argument.

Follow the prompts to analyze traffic, detect anomalies, and implement firewall rules.


Configuration:

Customize the threshold value for anomaly detection in the script.

Define trusted IP addresses in the whitelist.txt file to avoid blocking legitimate traffic.
