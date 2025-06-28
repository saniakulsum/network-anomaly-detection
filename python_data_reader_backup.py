import sys
from io import StringIO
from scapy.all import *
from scapy.layers.tls.all import *
import pandas as pd
from sklearn.ensemble import IsolationForest
import argparse 
import numpy as np
from collections import Counter
import math


def shannon_entropy(data):
    """
    Calculate Shannon entropy of bytes-like input
    """
    if not data:
        return 0.0
    counter = Counter(data)
    total = len(data)
    entropy = -sum((count / total) * math.log2(count / total) for count in counter.values())
    return entropy

parser = argparse.ArgumentParser(description="Advanced Network Analyzer")
parser.add_argument("--honeypot", action="store_true", help="Enable Honeypot Mode (Live Monitoring)")

args = parser.parse_args()

textTracer = "###[ SSL/TLS ]###"

inputFileName = "testing.pcap"
outFileName = "rawData.txt"

print("\U0001F50D Advanced Network Anomaly Detection System")
print("Data Parser by Umeer Mohammad - Student Code: 4748549\n")

if args.honeypot:
    print("\n================> 🛡️ HONEYPOT MODE ENABLED <=================")
    print("Listening for suspicious TCP SYN scans and responding with fake open ports...\n")

    def honeypot_callback(pkt):
        try:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                ip_layer = pkt[IP]
                tcp_layer = pkt[TCP]
                if tcp_layer.flags == "S":
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    print(f"🕵️ SYN scan detected from {src_ip}:{src_port} → {dst_ip}:{dst_port}")
                    response = IP(src=dst_ip, dst=src_ip) / TCP(
                        sport=dst_port,
                        dport=src_port,
                        flags="SA",
                        seq=1000,
                        ack=tcp_layer.seq + 1
                    )
                    send(response, verbose=False)
                    print(f"📱 Sent fake SYN-ACK to {src_ip}:{src_port}")
                    with open("honeypot_log.txt", "a") as f:
                        f.write(f"{pd.Timestamp.now()} | SYN from {src_ip}:{src_port} → {dst_ip}:{dst_port}\n")
        except Exception as e:
            print(f"❌ Error in honeypot callback: {e}")

    sniff(filter="tcp", prn=honeypot_callback, store=0)
    sys.exit(0)

if len(sys.argv) == 2:
    inputFileName = sys.argv[1]
else:
    print("⚠️  Warning: The pcap file is not specified hence the testing.pcap will be automatically used...\n")


print("==================> PACKET ANALYSIS & ML PROCESSING <=====================")

packets = rdpcap(inputFileName)
print(f"📊 Total packets loaded: {len(packets)}")

# Enhanced data collection with more features
data = []
packet_details = []
port_frequencies = {}
length_stats = []

print("\n🔄 Processing packets...")

for counter, packet in enumerate(packets, 1):
    if counter % 100 == 0:
        print(f"   Processed {counter}/{len(packets)} packets...")
    
    # Basic features
    length = len(packet)
    sport = packet.sport if hasattr(packet, 'sport') else 0
    dport = packet.dport if hasattr(packet, 'dport') else 0
    is_tls = 1 if textTracer in packet.show(dump=True) else 0
    
    # Enhanced features for better anomaly detection
    protocol = packet.proto if hasattr(packet, 'proto') else 0
    has_payload = 1 if hasattr(packet, 'payload') and len(packet.payload) > 0 else 0
    
    # Additional network features with proper type conversion
    tcp_flags = 0
    udp_flag = 0
    icmp_flag = 0
    
    try:
        if packet.haslayer(TCP):
            # Convert TCP flags to integer value
            tcp_flags = int(packet[TCP].flags) if hasattr(packet[TCP], 'flags') else 0
        elif packet.haslayer(UDP):
            udp_flag = 1
        elif packet.haslayer(ICMP):
            icmp_flag = 1
    except (ValueError, TypeError):
        # Handle any conversion errors
        tcp_flags = 0

    try:
        raw_bytes = bytes(packet.payload) if hasattr(packet, 'payload') else b''
        entropy = shannon_entropy(raw_bytes)
    except:
        entropy = 0.0
    
    # Track statistics for anomaly classification
    length_stats.append(length)
    if sport not in port_frequencies:
        port_frequencies[sport] = 0
    port_frequencies[sport] += 1
    
    # Store detailed packet information
    packet_info = {
        'packet_id': counter,
        'timestamp': packet.time if hasattr(packet, 'time') else 0,
        'src_ip': packet.src if hasattr(packet, 'src') else 'Unknown',
        'dst_ip': packet.dst if hasattr(packet, 'dst') else 'Unknown',
        'protocol_name': packet.name if hasattr(packet, 'name') else 'Unknown',
        'raw_length': length,
        'raw_sport': sport,
        'raw_dport': dport
    }
    
    data.append([length, sport, dport, is_tls, protocol, has_payload, tcp_flags, udp_flag, icmp_flag,entropy])
    packet_details.append(packet_info)

print(f"✅ Packet processing complete!\n")

# Calculate statistics for anomaly classification
length_mean = np.mean(length_stats)
length_std = np.std(length_stats)
length_q1 = np.percentile(length_stats, 25)
length_q3 = np.percentile(length_stats, 75)
common_ports = set([21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995])
high_frequency_ports = set([port for port, freq in port_frequencies.items() if freq > len(packets) * 0.05])

print("📈 Network Traffic Statistics:")
print(f"   Average packet length: {length_mean:.2f} bytes")
print(f"   Standard deviation: {length_std:.2f} bytes")
print(f"   Most frequent ports: {sorted(list(high_frequency_ports))[:10]}")

# Create dataframe
df = pd.DataFrame(data, columns=['length', 'sport', 'dport', 'is_tls', 'protocol', 'has_payload', 'tcp_flags', 'udp_flag', 'icmp_flag' , 'entropy' ])
details_df = pd.DataFrame(packet_details)

print("\n🤖 Training Machine Learning Model...")

# Train Isolation Forest with enhanced features
clf = IsolationForest(contamination=0.1, random_state=42, n_estimators=100)
features_for_ml = ['length', 'sport', 'dport', 'is_tls', 'protocol', 'has_payload', 'tcp_flags', 'udp_flag', 'icmp_flag' , 'entropy' ]
df['anomaly'] = clf.fit_predict(df[features_for_ml])

# Get anomaly scores (lower = more anomalous)
df['anomaly_score'] = clf.decision_function(df[features_for_ml])

# Combine with packet details
result_df = pd.concat([details_df, df], axis=1)

print("✅ Machine Learning Analysis Complete!\n")

# ADVANCED ANOMALY TYPE CLASSIFICATION
def classify_anomaly_type(packet_row, length_mean, length_std, common_ports, high_frequency_ports):
    """
    Classify the specific type of anomaly based on packet characteristics
    """
    anomaly_types = []
    confidence_scores = {}
    
    length = packet_row['raw_length']
    sport = packet_row['raw_sport']
    dport = packet_row['raw_dport']
    is_tls = packet_row['is_tls']
    tcp_flags = packet_row['tcp_flags']
    anomaly_score = packet_row['anomaly_score']
    entropy = packet_row['entropy']

    # 1. SIZE-BASED ANOMALIES
    if length > length_mean + 3 * length_std:
        anomaly_types.append("JUMBO_PACKET_ATTACK")
        confidence_scores["JUMBO_PACKET_ATTACK"] = min(95, 70 + abs(anomaly_score) * 100)
    elif length < 64 and length > 0:
        anomaly_types.append("MICRO_PACKET_ATTACK")
        confidence_scores["MICRO_PACKET_ATTACK"] = min(90, 60 + abs(anomaly_score) * 100)
    elif length == 0:
        anomaly_types.append("NULL_PACKET_ANOMALY")
        confidence_scores["NULL_PACKET_ANOMALY"] = 95
    
    # 2. PORT-BASED ANOMALIES
    if sport > 65000 or dport > 65000:
        anomaly_types.append("HIGH_PORT_SCANNING")
        confidence_scores["HIGH_PORT_SCANNING"] = min(85, 50 + abs(anomaly_score) * 100)
    
    if sport in common_ports and dport in common_ports:
        anomaly_types.append("SUSPICIOUS_PORT_COMBINATION")
        confidence_scores["SUSPICIOUS_PORT_COMBINATION"] = min(80, 45 + abs(anomaly_score) * 100)
    
    if sport not in high_frequency_ports and sport not in common_ports and sport > 1024:
        anomaly_types.append("UNCOMMON_SOURCE_PORT")
        confidence_scores["UNCOMMON_SOURCE_PORT"] = min(75, 40 + abs(anomaly_score) * 100)
    
    # 3. PROTOCOL-BASED ANOMALIES
    if is_tls == 1 and (dport != 443 and dport != 993 and dport != 995):
        anomaly_types.append("TLS_ON_UNUSUAL_PORT")
        confidence_scores["TLS_ON_UNUSUAL_PORT"] = min(90, 65 + abs(anomaly_score) * 100)
    
    # 4. TCP FLAGS ANOMALIES
    if tcp_flags > 0:
        if tcp_flags == 2:  # SYN only
            if sport == dport:
                anomaly_types.append("LAND_ATTACK_PATTERN")
                confidence_scores["LAND_ATTACK_PATTERN"] = 95
        elif tcp_flags == 1:  # FIN only
            anomaly_types.append("FIN_SCAN_ATTEMPT")
            confidence_scores["FIN_SCAN_ATTEMPT"] = min(85, 55 + abs(anomaly_score) * 100)
        elif tcp_flags == 41:  # FIN+URG+PSH
            anomaly_types.append("XMAS_SCAN_ATTEMPT")
            confidence_scores["XMAS_SCAN_ATTEMPT"] = 90
        elif tcp_flags == 0:  # No flags
            anomaly_types.append("NULL_SCAN_ATTEMPT")
            confidence_scores["NULL_SCAN_ATTEMPT"] = 85
    
    # 5. BEHAVIORAL ANOMALIES
    if length > 1500:  # Larger than typical MTU
        anomaly_types.append("FRAGMENTATION_ATTACK")
        confidence_scores["FRAGMENTATION_ATTACK"] = min(80, 50 + abs(anomaly_score) * 100)
    
    if sport < 1024 and dport < 1024:
        anomaly_types.append("PRIVILEGE_ESCALATION_ATTEMPT")
        confidence_scores["PRIVILEGE_ESCALATION_ATTEMPT"] = min(70, 35 + abs(anomaly_score) * 100)
    
    if entropy > 7.5:
        anomaly_types.append("HIGH_PAYLOAD_ENTROPY")
        confidence_scores["HIGH_PAYLOAD_ENTROPY"] = min(95, 70 + abs(anomaly_score) * 100)
    elif entropy > 0 and entropy < 3:
        anomaly_types.append("LOW_PAYLOAD_ENTROPY")
        confidence_scores["LOW_PAYLOAD_ENTROPY"] = min(70, 40 + abs(anomaly_score) * 100)

    # 6. GENERAL ANOMALY CLASSIFICATION
    if abs(anomaly_score) > 0.5:
        anomaly_types.append("SEVERE_BEHAVIORAL_ANOMALY")
        confidence_scores["SEVERE_BEHAVIORAL_ANOMALY"] = min(95, 80 + abs(anomaly_score) * 50)
    elif abs(anomaly_score) > 0.2:
        anomaly_types.append("MODERATE_ANOMALY")
        confidence_scores["MODERATE_ANOMALY"] = min(75, 60 + abs(anomaly_score) * 50)
    
    # If no specific type identified, classify as general
    if not anomaly_types:
        anomaly_types.append("UNKNOWN_BEHAVIORAL_ANOMALY")
        confidence_scores["UNKNOWN_BEHAVIORAL_ANOMALY"] = min(60, 30 + abs(anomaly_score) * 100)
    
    return anomaly_types, confidence_scores

# Analyze anomalous packets with detailed classification
print("==================> 🚨 DETAILED ANOMALY ANALYSIS 🚨 <=====================")

anomalous_packets = result_df[result_df['anomaly'] == -1].copy()

if len(anomalous_packets) > 0:
    print(f"🔍 DETECTED {len(anomalous_packets)} ANOMALOUS PACKETS out of {len(result_df)} total packets")
    print(f"📊 Anomaly Rate: {(len(anomalous_packets)/len(result_df)*100):.2f}%\n")
    
    # Classify each anomalous packet
    all_anomaly_types = []
    
    for idx, packet in anomalous_packets.iterrows():
        anomaly_types, confidence_scores = classify_anomaly_type(
            packet, length_mean, length_std, common_ports, high_frequency_ports
        )
        
        all_anomaly_types.extend(anomaly_types)
        
        print(f"🚨 ANOMALOUS PACKET #{packet['packet_id']}")
        print(f"   📈 Anomaly Score: {packet['anomaly_score']:.4f} (lower = more suspicious)")
        print(f"   🌐 Source: {packet['src_ip']}:{packet['raw_sport']}")
        print(f"   🎯 Destination: {packet['dst_ip']}:{packet['raw_dport']}")
        print(f"   📏 Length: {packet['raw_length']} bytes")
        print(f"   🔒 TLS Encrypted: {'Yes' if packet['is_tls'] else 'No'}")
        print(f"   ⏰ Timestamp: {packet['timestamp']}")
        
        print(f"   🏷️  DETECTED ANOMALY TYPES:")
        for anomaly_type in anomaly_types:
            confidence = confidence_scores.get(anomaly_type, 50)
            risk_level = "HIGH" if confidence > 80 else "MEDIUM" if confidence > 60 else "LOW"
            print(f"      ▶️ {anomaly_type.replace('_', ' ').title()}")
            print(f"         Confidence: {confidence:.1f}% | Risk Level: {risk_level}")
        
        print("   " + "="*60)
        print()
    
    # Summary of anomaly types
    print("📋 ANOMALY TYPE SUMMARY:")
    anomaly_counter = Counter(all_anomaly_types)
    for anomaly_type, count in anomaly_counter.most_common():
        print(f"   🔸 {anomaly_type.replace('_', ' ').title()}: {count} occurrences")
    
else:
    print("✅ No anomalous packets detected. Network traffic appears normal.")

# Enhanced summary statistics
print(f"\n==================> 📊 COMPREHENSIVE ANALYSIS SUMMARY 📊 <=====================")
print(f"🔢 Total packets analyzed: {len(result_df)}")
print(f"✅ Normal packets: {len(result_df[result_df['anomaly'] == 1])}")
print(f"🚨 Anomalous packets: {len(result_df[result_df['anomaly'] == -1])}")
print(f"📏 Average packet length: {df['length'].mean():.2f} bytes")
print(f"🔒 TLS encrypted packets: {df['is_tls'].sum()}")
print(f"🌐 TCP packets: {df['tcp_flags'].astype(bool).sum()}")
print(f"📡 UDP packets: {df['udp_flag'].sum()}")
print(f"📢 ICMP packets: {df['icmp_flag'].sum()}")

# Enhanced output with anomaly types
result_df['anomaly_types'] = ''
result_df['confidence_scores'] = ''

for idx, packet in result_df[result_df['anomaly'] == -1].iterrows():
    anomaly_types, confidence_scores = classify_anomaly_type(
        packet, length_mean, length_std, common_ports, high_frequency_ports
    )
    result_df.at[idx, 'anomaly_types'] = '; '.join(anomaly_types)
    result_df.at[idx, 'confidence_scores'] = '; '.join([f"{k}:{v:.1f}%" for k, v in confidence_scores.items()])

# Save comprehensive results
result_df.to_csv("comprehensive_anomaly_analysis.csv", index=False)
print(f"\n💾 Complete analysis saved to: comprehensive_anomaly_analysis.csv")
print(f"✅ Advanced anomaly detection complete!")

# Generate summary report
summary_report = f"""
🔍 NETWORK ANOMALY DETECTION REPORT
=====================================
Analysis Date: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}
Input File: {inputFileName}

📊 STATISTICS:
- Total Packets: {len(result_df)}
- Normal Packets: {len(result_df[result_df['anomaly'] == 1])}
- Anomalous Packets: {len(result_df[result_df['anomaly'] == -1])}
- Anomaly Rate: {(len(result_df[result_df['anomaly'] == -1])/len(result_df)*100):.2f}%

🏷️ DETECTED THREAT TYPES:
{chr(10).join([f"- {anomaly_type.replace('_', ' ').title()}: {count} occurrences" for anomaly_type, count in Counter(all_anomaly_types).most_common()]) if 'all_anomaly_types' in locals() and all_anomaly_types else "- No specific threats detected"}

🎯 RECOMMENDATION:
{"Further investigation recommended for detected anomalies." if len(anomalous_packets) > 0 else "Network traffic appears normal."}
"""

with open("anomaly_detection_report.txt", "w") as f:
    f.write(summary_report)

print(f"📄 Summary report saved to: anomaly_detection_report.txt")
print("\n🎉 Analysis Complete! Ready for presentation to supervisor.")

