# 🛡️ Sentinel-AI SIEM System

Welcome to the **Next-Gen AI SIEM** (Security Information and Event Management) project. Built in Python, this system is designed to secure your infrastructure by collecting, analyzing, and detecting anomalies in system logs in real-time, utilizing Machine Learning, Large Language Models, and advanced rule engines.

This project was recently **upgraded from a prototype to a production-ready application** featuring robust error handling, secure credential management, asynchronous processing, and a microservices Docker architecture.

## 🚀 Key Features

*   **⚡ High-Performance Async Architecture:** Built on FastAPI, `asyncio`, and `aiohttp`. Capable of handling massive log ingestion without blocking the event loop.
*   **🧠 LLM-Driven Threat Intelligence:** Leverages Large Language Models (Gemini/Ollama) to perform heuristic contextual analysis, explaining the *intent* behind logs and offering actionable remediation advice.
*   **🔮 Machine Learning Anomaly Detection:** Uses `scikit-learn`'s Isolation Forest algorithm to detect deviations from baseline system behavior in real-time.
*   **🚨 Stateful Rule Engine:** Tracks frequency-based threats (e.g., Brute Force, Credential Stuffing, Privilege Escalation) using sliding time windows to prevent alert fatigue.
*   **🛑 Automated Mitigation:** *Sentinel-AI* actively intercepts critical threats, simulating IAM revocation and IP-level firewall blocks via a dedicated fire-and-forget mitigation subsystem.
*   **📊 Observability & Storage:** 
    *   **Elasticsearch:** Primary durable storage for forensic search and historical data correlation (with TLS enforcement).
    *   **Splunk Integration:** Asynchronous HTTP Event Collector (HEC) forwarding for native exploration within Splunk Enterprise.
    *   **Streamlit Dashboard:** A live, glassmorphism-styled command center for monitoring threats and viewing AI insights.

---

## 🏗️ Architecture Stack

*   **Core Logic:** Python 3.11+
*   **API Layer:** FastAPI, Uvicorn, Pydantic
*   **Data Science:** Pandas, NumPy, Scikit-Learn, VADER Sentiment
*   **Infrastructure:** Docker Compose, Elasticsearch (Async), Splunk
*   **UI:** Streamlit, Altair

---

## 📥 Installation & Quick Start

### Prerequisites
*   **Docker Desktop:** [Download Here](https://www.docker.com/products/docker-desktop/)
*   **Git:** [Download Here](https://git-scm.com/downloads)

### 1. Clone the Repository
```bash
git clone https://github.com/Shafiyullah/siem-cyber.git
cd siem-cyber
```

### 2. Configure the Environment
The application is strictly governed by environment variables to prevent accidental secret leaks.

1.  Copy the provided secure template:
    ```bash
    cp .env.example .env
    ```
2.  Open `.env` in your text editor and fill in your actual secrets, API keys, and passwords.
3.  *Note: The system will refuse to start if critical variables (like `API_KEY`) are missing.*

### 3. Run with Docker Compose
Start the entire microservices stack (SIEM Engine, Elasticsearch, and Splunk) inside an isolated Docker network:

```bash
docker-compose up --build -d
```
*Wait ~60 seconds for Elasticsearch and Splunk to fully initialize and pass their health checks.*

---

## 🎮 How to Use

### 1. Accessing the Interfaces
Once the Docker containers are healthy, you can access the following services:

*   **Sentinel-AI API Docs:** `http://localhost:8001/docs` *(Requires the `API_KEY` you set in `.env`)*
*   **Streamlit Command Center:** `http://localhost:8501`
*   **Splunk Enterprise:** `http://localhost:8000` *(Log in with `admin` and your `SPLUNK_PASSWORD`)*
*   **Elasticsearch (Sanity Check):** `https://localhost:9200` *(Or `http://` if you disabled TLS)*

### 2. Simulating Log Ingestion
By default, the collector tails the files defined in your `LOG_SOURCES` environment variable (e.g., `./test_logs.txt`).

Trigger a brute-force rule by appending to your test log file:
```bash
echo "2026-01-01T12:00:00 Failed password for invalid user from 192.168.1.50 port 22 ssh2" >> test_logs.txt
echo "2026-01-01T12:00:01 Failed password for invalid user from 192.168.1.50 port 22 ssh2" >> test_logs.txt
echo "2026-01-01T12:00:02 Failed password for invalid user from 192.168.1.50 port 22 ssh2" >> test_logs.txt
echo "2026-01-01T12:00:03 Failed password for invalid user from 192.168.1.50 port 22 ssh2" >> test_logs.txt
echo "2026-01-01T12:00:04 Failed password for invalid user from 192.168.1.50 port 22 ssh2" >> test_logs.txt
```

### 3. Fetching Alerts
Query the API to fetch processed security alerts:
```bash
curl -H "X-API-Key: <YOUR_API_KEY>" "http://localhost:8001/alerts?severity=high&limit=10"
```

---

## 🔒 Security Posture

*   **Secret Management:** No hardcoded credentials. Enforced use of `.env` files via `Config` validation.
*   **Authentication:** API routes protected by constant-time secret comparison (`secrets.compare_digest`).
*   **Input Validation:** Strict Pydantic models with path-traversal guards and payload size limits to prevent DoS.
*   **Network Isolation:** Docker services run on a dedicated bridged network (`siem-net`).
*   **Defense in Depth:** TLS enforcement capabilities for database connections (`ES_USE_TLS`).

---

## 🛠️ Troubleshooting

*   **Container Crash (`siem-api` keeps restarting):** The most common cause is a missing or invalid `.env` file. Check the logs: `docker logs siem-api`.
*   **Splunk Connection Errors:** Ensure the `SPLUNK_HEC_TOKEN` in your `.env` exactly matches the token you've configured inside the Splunk UI.
*   **Elasticsearch Verification Failed:** If you left `ES_USE_TLS=true` in development without proper certificates, set it to `false` in `.env` and restart.

---

## 🤝 Contributing
Contributions, issues, and feature requests are welcome!

*Built with ❤️ for Cyber Security.*
