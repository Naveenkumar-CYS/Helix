# 🍯 AI Honeypot

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.68%2B-green)
![License](https://img.shields.io/badge/License-MIT-purple)
![Status](https://img.shields.io/badge/Status-Active-success)

A sophisticated, AI-powered deceptive honeypot designed to detect, analyze, and mislead attackers. This system goes beyond simple emulation by using LLMs to generate realistic responses, machine learning to classify attacks, and advanced fingerprinting to identify adversaries.

## 🚀 Key Features

The AI Honeypot includes **21 intelligence modules** working in harmony to provide a complete threat detection and analysis platform:

### 🧠 Advanced Intelligence
- **LLM-Powered Responses**: Generates realistic, context-aware content to keep attackers engaged.
- **ML Attack Classification**: Uses machine learning to classify attacks and detect anomalies in real-time.
- **Behavioral Profiling**: Identifies attacker skill levels (Novice, Intermediate, Advanced, Automated).
- **Campaign Detection**: correlates multi-vector attacks and tracks campaigns across sessions.
- **🆕 Attack Prediction**: AI-powered Markov chain model predicts next attack vectors and time-to-compromise.
- **🆕 MITRE ATT&CK Mapping**: Maps attacks to industry-standard framework with APT group matching.

### 🛡️ Deception & Evasion
- **Realistic Latency**: Simulates natural processing delays (50-800ms) to avoid detection as a honeypot.
- **Fake Vulnerabilities**: Intentionally exposes fake flaws to lure attackers into revealing their methods.
- **Canary Tokens**: Embeds unique, trackable tokens in responses (credentials, API keys) to detect data leaks.
- **Tool Poisoning**: Specifically targets and confuses common attack tools like SQLMap and Burp Suite.
- **🆕 Adaptive Deception**: Adjusts difficulty based on attacker skill level (easy for novices, rabbit holes for experts).

### 📊 Monitoring & Analysis
- **Real-Time Dashboard**: Live visualization of attacks, traffic, and threat metrics via WebSocket.
- **Threat Intelligence**: Integrates with AbuseIPDB and VirusTotal for external IP reputation scoring.
- **Browser Fingerprinting**: Advanced tracking using Canvas, WebGL, and AudioContext fingerprinting.
- **Interactive Shell**: specific simulation of a compromised environment with fake file system and admin panels.
- **🆕 Forensic Timeline**: Complete attack replay with adjustable speed and narrative generation.
- **🆕 Canary Analytics**: Advanced tracking of token extraction, usage, and effectiveness scoring.

### 🔄 Automation & Integration
- **🆕 Threat Intelligence Sharing**: Export IOCs, STIX 2.1 bundles, and threat reports.
- **🆕 Incident Response Playbooks**: Auto-generate response guides and Sigma rules for SIEM.
- **🆕 Data Export**: CSV, JSON, and formatted exports for analysis.
- **🆕 Docker Deployment**: One-command deployment with docker-compose.

## 📂 Project Structure

```
├── app.py                   # Main FastAPI application entry point
├── llm_engine.py            # LLM-based response generation
├── ml_classifier.py         # Machine learning for attack classification
├── dashboard.py             # Real-time web dashboard logic
├── deception_engine.py      # Handling timing, errors, and realism
├── behavioral_analyzer.py   # Skill level and behavior analysis
├── threat_intel.py          # External threat intelligence integration
├── alerts.py                # Notification system (Slack/Discord)
├── attack_predictor.py      # 🆕 AI-powered attack prediction
├── mitre_mapper.py          # 🆕 MITRE ATT&CK framework mapping
├── forensic_timeline.py     # 🆕 Attack replay and forensics
├── canary_analytics.py      # 🆕 Canary token analytics
├── adaptive_deception.py    # 🆕 Skill-adaptive deception
├── threat_sharing.py        # 🆕 IOC/STIX threat intelligence export
├── playbook_generator.py    # 🆕 Incident response automation
├── export_engine.py         # 🆕 Multi-format data export
├── Dockerfile               # 🆕 Docker containerization
├── docker-compose.yml       # 🆕 One-command deployment
└── attacks.log              # Structured log of all detected activities
```

## ⚡ Quick Start

### 🐳 Docker (Recommended)

The fastest way to get started:

```bash
# Clone the repository
git clone https://github.com/madhurgrover-cs/ai-honepot.git
cd ai-honepot

# Start with Docker Compose
docker-compose up --build
```

Access the honeypot at `http://localhost:8000`

See [DOCKER.md](DOCKER.md) for more details.

### 🐍 Manual Installation

### Prerequisites
- Python 3.8+
- pip

### Installation

1.  **Clone the repository**
    ```bash
    git clone https://github.com/madhurgrover-cs/ai-honepot.git
    cd ai-honepot
    ```

2.  **Create a virtual environment**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies**
    ```bash
    pip install -r requirements.txt
    ```

### Running the Honeypot

Start the server:
```bash
python app.py
```
The honeypot will start on `http://0.0.0.0:8000`.

### Accessing the Dashboard

Visit `http://localhost:8000/dashboard` to view the real-time attack monitor.

## 🧪 Testing

To verify the honeypot's functionality, run the included test suite:
```bash
python test_honeypot.py
```

You can also manually simulate attacks:

*   **SQL Injection**: `curl "http://localhost:8000/search?q=' OR 1=1--"`
*   **Admin Access**: `curl "http://localhost:8000/admin"`
*   **XSS Attempt**: `curl "http://localhost:8000/search?q=<script>alert(1)</script>"`

## ⚙️ Configuration

The system is designed to work out-of-the-box with sensible defaults.

### External Threat Intelligence
To enable AbuseIPDB and VirusTotal integration, you can configure your API keys in `external_threat_intel.py` or call `configure_threat_intel()` in your startup script.

### Alerts
Webhooks for Slack and Discord can be configured in `alerts.py`.

## 📝 Documentation

Detailed documentation is available in the project repository:
- [FEATURES.md](FEATURES.md) - Complete feature list
- [QUICKSTART.md](QUICKSTART.md) - Extended usage guide
- [ADVANCED_FEATURES.md](ADVANCED_FEATURES.md) - Deep dive into ML and deception modules
- [TEST_RESULTS.md](TEST_RESULTS.md) - Verification and performance metrics

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
