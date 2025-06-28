import pandas as pd
import matplotlib.pyplot as plt

# Load CSV
df = pd.read_csv("packet_ml_output.csv")

# Print summary
num_packets = len(df)
num_anomalies = df['is_anomaly'].sum()
num_normal = num_packets - num_anomalies

print(f"✅ Packets analyzed: {num_packets}")
print(f"⚠ Anomalies detected: {num_anomalies}")
print(f"✅ Normal packets: {num_normal}")

# Plot
plt.figure(figsize=(10, 6))

# Plot normal packets
normal = df[df['is_anomaly'] == 0]
plt.scatter(normal['src_port'], normal['dst_port'], c='green', label='Normal', alpha=0.6)

# Plot anomalies
anomalies = df[df['is_anomaly'] == 1]
plt.scatter(anomalies['src_port'], anomalies['dst_port'], c='red', label='Anomaly', alpha=0.9)

plt.xlabel("Source Port")
plt.ylabel("Destination Port")
plt.title("Packet Anomaly Detection (Source vs Destination Port)")
plt.legend()
plt.grid(True)

# Show plot
plt.show()
