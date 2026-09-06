# OCTOPUS 🐙

Modular CLI cybersecurity & authorized security-testing toolkit.

## Safety / legal model
- Everything here is limited to **assets you own or are authorized to test.**
- **OSINT** touches only public endpoints (no auth, no scraping engines).
- **Network scans** require an explicit authorization confirmation per target.
- **Load testing** has hard safety caps and no DDoS/amplification/spoof/botnet.
- **Main menu [6] "DDoS"** does not run a real DDoS tool — it redirects you to
  the controlled load tester and explains why.

## Install
```bash
cd octopus
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python octopus.py
