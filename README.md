# 🛡️ AI-Powered SIEM System

Welcome to the **Next-Gen AI SIEM** (Security Information and Event Management) project. This system is designed to secure your infrastructure by collecting, analyzing, and detecting anomalies in system logs using advanced Machine Learning and AI.

## 🚀 Key Features

- **⚡ High Performance**: Built on a fully asynchronous architecture for maximum speed and throughput.
- **🧠 AI Analysis**: Uses Log-LLM (Large Language Model) integration to explain *why* a log is suspicious.
- **🔮 Anomaly Detection**: Automatically flags unusual behavior using configurable Isolation Forest algorithms.
- **🛡️ Automated Mitigation**: *Sentinel-AI* actively intercepts brute-force and privilege escalation attacks, simulating IAM and IP-level blocks.
- **📈 Splunk Integration**: Real-time HTTP Event Collector (HEC) forwarding for native exploration within Splunk Enterprise.
- **🔍 Elastic Storage**: Stores millions of logs for instant retrieval and forensic search.

---

## 📥 How to Download & Install

### Prerequisites
- **Docker Desktop**: [Download Here](https://www.docker.com/products/docker-desktop/)
- **Git**: [Download Here](https://git-scm.com/downloads)

### Installation Steps

1.  **Clone the Repository**
    Open your terminal (PowerShell or Command Prompt) and run:
    ```bash
    git clone https://github.com/Shafiyullah/siem-cyber.git
    ```
    ```bash
    cd siem-cyber
    ```    

2.  **Configure Environment**
    Copy the provided `.env.example` file to `.env` to configure your installation:
    ```bash
    cp .env.example .env
    ```
    *Open `.env` in a text editor and fill in your secrets. The system will not start unless the `API_KEY` is set!*

3.  **Run with Docker (Recommended)**
    Start the entire system with one command:
    ```bash
    docker-compose up --build -d
    ```
    *This will start Elasticsearch, Splunk Enterprise, and the SIEM API Engine inside an isolated Docker network.*

---

## 🎮 How to Use

### 1. Accessing the Interfaces
Once running, open your browser to access the dashboards:
- **SIEM API Docs**: `http://localhost:8001/docs` *(Requires API Key Authorization)*
- **SIEM Health Check**: `http://localhost:8001/health`
- **Splunk Enterprise**: `http://localhost:8000` *(Log in with `admin` and your `SPLUNK_PASSWORD`)*

### 2. Monitoring Logs
The system automatically monitors logs defined in `config.py` (default: `test_logs.txt` on Windows, `/var/log/syslog` on Linux).
To simulate a threat, add a suspicious log line to `test_logs.txt`:
```text
2025-01-01T12:00:00 Failed password for user root from 192.168.1.50 port 22 ssh2
```
*The system will detect this within seconds!*

### 3. Checking Alerts
Use the API to fetch security alerts:
```bash
curl -H "X-API-Key: your-secure-api-key" http://localhost:8001/alerts?severity=high
```

---

## 🛠️ Troubleshooting

- **"Connection Refused"**: Ensure Docker is running (`docker ps`). Wait 30 seconds for Elasticsearch to fully start.
- **"No Logs Found"**: Check if `test_logs.txt` exists and has data. The system waits for this file to be created.
- **"Memory Error"**: Elasticsearch uses significant RAM. Ensure Docker has at least 4GB allocated.

---

## 🤝 Contributing
We welcome contributions! Please fork the repo and submit a Pull Request.

---
*Built with ❤️ for Cyber Security.*
