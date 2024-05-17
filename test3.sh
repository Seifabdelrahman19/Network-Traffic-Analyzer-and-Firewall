#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <path_to_pcap_file>"
    exit 1
fi

pcap_file="$1"
whitelist_file="whitelist.txt"

whitelist_ips=()
if [ -f "$whitelist_file" ]; then
    mapfile -t whitelist_ips < "$whitelist_file"
fi

is_whitelisted() {
    local ip="$1"
    for whitelist_ip in "${whitelist_ips[@]}"; do
        if [ "$ip" == "$whitelist_ip" ]; then
            return 0
        fi
    done
    return 1
}

analyze_traffic() {
    total_packets=$(tshark -r "$pcap_file" 2>/dev/null | wc -l)
    http_packets=$(tshark -r "$pcap_file" -Y "http" 2>/dev/null | wc -l)
    https_packets=$(tshark -r "$pcap_file" -Y "tls" 2>/dev/null | wc -l)

    top_src_ips=$(tshark -r "$pcap_file" -T fields -e ip.src 2>/dev/null | sort | uniq -c | sort -nr | head -n 10)
    top_dst_ips=$(tshark -r "$pcap_file" -T fields -e ip.dst 2>/dev/null | sort | uniq -c | sort -nr | head -n 10)

    echo "----- Network Traffic Analysis Report -----"
    echo "1. Total Packets: $total_packets"
    echo "2. Protocols:"
    echo "   - HTTP: $http_packets packets"
    echo "   - HTTPS/TLS: $https_packets packets"
    echo ""
    echo "3. Top 10 Source IP Addresses:"
    echo "$top_src_ips"
    echo ""
    echo "4. Top 10 Destination IP Addresses:"
    echo "$top_dst_ips"
    echo ""
    echo "----- End of Report -----"
}

detect_anomalies() {
    local threshold=1000
    echo "Checking for anomalies..."
    anomalies=$(tshark -r "$pcap_file" -T fields -e ip.src 2>/dev/null | sort | uniq -c | awk -v threshold="$threshold" '$1 > threshold {print $2}')

    if [ -n "$anomalies" ]; then
        echo "Suspicious patterns detected from the following IP addresses:"
        for anomaly in $anomalies; do
            if ! is_whitelisted "$anomaly"; then
                echo "$anomaly"
            else
                echo "$anomaly is whitelisted."
            fi
        done
        echo ""
        implement_firewall_rules "$anomalies"
    else
        echo "No anomalies detected."
    fi
}

implement_firewall_rules() {
    local ips="$1"
    for ip in $ips; do
        if ! is_whitelisted "$ip"; then
            echo "Blocking suspicious IP address: $ip"
            if sudo iptables -A INPUT -s "$ip" -j DROP && sudo iptables -A OUTPUT -d "$ip" -j DROP; then
                echo "Firewall rules implemented."
            else
                echo "Failed to implement firewall rules for IP address: $ip"
            fi
        fi
    done
}

analyze_traffic
detect_anomalies

echo "Network monitoring and firewall rule implementation completed."

