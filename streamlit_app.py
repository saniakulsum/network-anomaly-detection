import streamlit as st
import subprocess
import os
import pandas as pd
import time

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
                st.download_button("📥 Download Honeypot Log", data=open("honeypot_log.txt").read(), file_name="honeypot_log.txt")

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

                    st.dataframe(df.head(100))

                    st.download_button("📄 Download Full CSV Report", data=open("comprehensive_anomaly_analysis.csv").read(), file_name="comprehensive_anomaly_analysis.csv")
                
                if os.path.exists("anomaly_detection_report.txt"):
                    with open("anomaly_detection_report.txt") as f:
                        summary = f.read()
                        st.text_area("📝 Summary Report", value=summary, height=300)
                        st.download_button("📥 Download Summary Report", data=summary, file_name="anomaly_detection_report.txt")
