# Network Anomaly Detection System

This project provides a **Streamlit-based GUI** for visualizing and detecting **network anomalies using honeypot data** for cybersecurity research and monitoring.

---

## Features

✅ Real-time network anomaly detection
✅ Clean Streamlit dashboard
✅ Honeypot data collection and visualization
✅ Lightweight, runs inside Ubuntu WSL

---

## Installation

1. Ensure you have **Ubuntu WSL installed** on your system.

2. Clone this repository (or place your project folder inside WSL):

```bash
git clone <repository_link>
```

3. Navigate to the project directory:

```bash
cd ~/honeypot_project/Task1
```

4. (Recommended) Create and activate a virtual environment:

```bash
python3 -m venv honeypot_env
source honeypot_env/bin/activate
```

5. Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Running the Application

Run the following steps inside your **Ubuntu WSL terminal**:

1. Navigate to your project:

```bash
cd ~/honeypot_project/Task1
```

2. Activate your virtual environment:

```bash
source honeypot_env/bin/activate
```

3. Run the Streamlit app:

```bash
streamlit run streamlit_app.py
```

---

## Simulating Network Traffic

To test the anomaly detection, simulate a **network scan** using `nmap` from any WSL terminal:

```bash
sudo nmap -sS -p 22,80,443 127.0.0.1
```

This will generate traffic for the honeypot to detect and display on the Streamlit dashboard.

---

## Screenshots

Embed screenshots of your dashboard for clarity:

```markdown
### Dashboard Overview

![Dashboard](screenshots/dashboard.png)

### Anomaly Detected

![Anomaly](screenshots/anomaly_detected.png)
```

Replace with your actual screenshot paths for clean documentation.

---

## Requirements

* Ubuntu WSL (Windows Subsystem for Linux)
* Python 3.8+
* Streamlit
* Pandas
* Plotly
* nmap (for testing)

---

## License

Add your license here (MIT/Apache/Custom).
