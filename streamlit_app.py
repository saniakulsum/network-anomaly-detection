import streamlit as st
import subprocess
import os
import pandas as pd
from collections import Counter
import plotly.express as px

st.set_page_config(page_title="🧠 Network Anomaly Detection GUI", layout="wide")
st.title("🔍 Advanced Network Anomaly Detection System")

st.markdown("""
This Streamlit app wraps around the core detection engine (`python_data_reader.py`).

You can either:
- Run the **Honeypot live mode**
- Upload a `.pcap` file for **offline anomaly analysis**
""")

mode = st.sidebar.radio("Choose Mode", ["📡 Honeypot Mode", "📁 Analyze PCAP File"])

if mode == "📡 Honeypot Mode":
    st.subheader("🛡️ Honeypot Mode - SYN Scan Detection")

    if st.button("▶️ Start Honeypot Listener"):
        with st.spinner("Starting honeypot... Please wait (30s timeout)..."):
            result = subprocess.run([
                "python3", "python_data_reader.py", "--honeypot"
            ], capture_output=True, text=True)
            st.success("✅ Honeypot execution completed.")
            st.code(result.stdout)
            if os.path.exists("honeypot_log.txt"):
                st.download_button("📥 Download Honeypot Log",
                                   data=open("honeypot_log.txt").read(),
                                   file_name="honeypot_log.txt")

elif mode == "📁 Analyze PCAP File":
    st.subheader("📁 Offline PCAP Analysis")
    uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap", "pcapng"])

    if uploaded_file:
        with open("uploaded_file.pcap", "wb") as f:
            f.write(uploaded_file.read())

        st.success("✅ File uploaded successfully: uploaded_file.pcap")

        if st.button("🚀 Start Analysis"):
            with st.spinner("Running ML-based anomaly detection..."):
                result = subprocess.run([
                    "python3", "python_data_reader.py", "uploaded_file.pcap"
                ], capture_output=True, text=True)

                st.code(result.stdout)

                if os.path.exists("comprehensive_anomaly_analysis.csv"):
                    df = pd.read_csv("comprehensive_anomaly_analysis.csv")
                    st.success("✅ Anomaly analysis complete. Displaying results...")

                    # Metric Columns
                    c1, c2, c3, c4, c5, c6, c7 = st.columns(7)
                    total_packets = len(df)
                    safe_packets = df[df['anomaly'] == 1].shape[0]
                    anomalous_packets = df[df['anomaly'] == -1].shape[0]

                    c1.metric("📦 Total Packets", total_packets)
                    c2.metric("✅ Safe Packets", safe_packets)
                    c3.metric("🚨 Anomalous Packets", anomalous_packets)

                    # Per anomaly-type counts using str.contains for reliability
                    anomaly_types = [
                        "Unknown Behavioral Anomaly",
                        "Fragmentation Attack",
                        "High Payload Entropy",
                        "Jumbo Packet Attack"
                    ]
                    type_counts = {}
                    if 'anomaly_type' in df.columns:
                        for atype in anomaly_types:
                            count = df[
                                (df['anomaly'] == -1) &
                                (df['anomaly_type'].fillna("").str.contains(atype, case=False, na=False))
                            ].shape[0]
                            type_counts[atype] = count
                    else:
                        type_counts = {atype: 0 for atype in anomaly_types}

                    c4.metric("🔹 Unknown Behav.", type_counts["Unknown Behavioral Anomaly"])
                    c5.metric("🟡 Fragmentation", type_counts["Fragmentation Attack"])
                    c6.metric("🟠 High Entropy", type_counts["High Payload Entropy"])
                    c7.metric("🟣 Jumbo Packet", type_counts["Jumbo Packet Attack"])

                    # Pie Chart
                    st.markdown("### 📊 Anomaly Type Distribution")
                    pie_data = pd.DataFrame({
                        "Anomaly Type": list(type_counts.keys()),
                        "Count": list(type_counts.values())
                    })
                    fig_pie = px.pie(
                        pie_data,
                        names="Anomaly Type",
                        values="Count",
                        title="Anomaly Type Distribution",
                        color_discrete_sequence=px.colors.qualitative.Set3
                    )
                    st.plotly_chart(fig_pie, use_container_width=True)

                    # Bar Chart (shown only if there are detected anomalies)
                    st.markdown("### 📊 Anomaly Type Counts")
                    bar_data = pie_data[pie_data["Count"] > 0]
                    if not bar_data.empty:
                        fig_bar = px.bar(
                            bar_data,
                            x="Anomaly Type",
                            y="Count",
                            color="Anomaly Type",
                            text="Count",
                            title="Anomaly Type Counts",
                            color_discrete_sequence=px.colors.qualitative.Set3
                        )
                        st.plotly_chart(fig_bar, use_container_width=True)
                    else:
                        st.info("✅ No anomalies detected to visualize.")

                    # Display DataFrame preview
                    st.markdown("### 🗂️ **Preview of Anomaly Detection Results**")
                    st.dataframe(df.head(100), use_container_width=True)

                    st.download_button("📄 Download Full CSV Report",
                                       data=open("comprehensive_anomaly_analysis.csv").read(),
                                       file_name="comprehensive_anomaly_analysis.csv")

                # Display and download summary report if exists
                if os.path.exists("anomaly_detection_report.txt"):
                    with open("anomaly_detection_report.txt") as f:
                        summary = f.read()

                    st.markdown("### 📝 **Summary Report**")
                    st.text_area("Anomaly Detection Summary",
                                 value=summary,
                                 height=400)
                    st.download_button("📥 Download Summary Report",
                                       data=summary,
                                       file_name="anomaly_detection_report.txt")
