# 🔒 Automated Security Scanner with Email Alerts

## 📌 Overview
This Python script automates security vulnerability scanning using **Nmap** and **Shodan**.  
It detects **open ports, running services, and possible vulnerabilities**, then sends an **email alert** to the security team if issues are found.  

## 🚀 Features
✅ **Automated Nmap Scanning** – Detects open ports & running services  
✅ **Vulnerability Detection** – Uses Nmap scripts (`--script=vuln`) to identify risks  
✅ **Shodan Exposure Check** – Finds if the target is publicly exposed  
✅ **Email Alerts** – Notifies security teams via email when vulnerabilities are found  
✅ **Easy Integration** – Schedule with Cron for regular scanning  

---

## 🛠️ Installation

### 1️⃣ **Clone the Repository**
```bash
git clone https://github.com/marcotrejolemus/cybersecurity/security-scanner.git
cd security-scanner
### 2️⃣ Install Required Dependencies
pip install python-nmap requests shodan
### 3️⃣ Set Up SMTP Credentials
If using Gmail SMTP, enable App Passwords and replace the credentials in security_alert.py:

python
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_SENDER = "your_email@gmail.com"
EMAIL_PASSWORD = "your_app_password"
EMAIL_RECEIVER = "security_team@example.com"
📌 For Gmail Users: Generate an App Password here.

### 4️⃣ Get Your Shodan API Key
Log in to Shodan
Go to Account Settings
Copy your API Key and replace it in security_alert.py:
python

SHODAN_API_KEY = "your_shodan_api_key"
🎯 Usage
Run the Script Manually
bash

python security_alert.py
👉 Enter the target IP or domain when prompted.

### Schedule Regular Scans (Linux)
Run this script automatically every day at 2 AM using Cron:

bash

crontab -e
Add this line:

bash

0 2 * * * /usr/bin/python3 /path/to/security_alert.py
📧 Email Alert Example
If vulnerabilities are detected, the security team receives an email like this:

yaml

Subject: [SECURITY ALERT] Vulnerability Found on 192.168.1.10

Security Scan Report for 192.168.1.10

Host: 192.168.1.10 (example.local)
  - Port 22/tcp (ssh): open
    Possible Vulnerabilities:
      - sshv1: SSH Version 1 is outdated and insecure

  - Port 80/tcp (http): open
    Possible Vulnerabilities:
      - http-shellshock: Server is vulnerable to Shellshock!

[+] Shodan Exposure for 192.168.1.10
  - IP: 192.168.1.10
  - Organization: Example Corp
  - OS: Linux
  - Open Ports: [22, 80]
🔐 Security Best Practices
⚠️ Never expose your API keys or passwords in public repositories.
Use environment variables instead:
Use Python to scan 
python

import os
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
Set them before running the script:

bash

export EMAIL_PASSWORD="your_app_password"
export SHODAN_API_KEY="your_shodan_api_key"
🛠️ Future Enhancements
🔹 Slack/Discord Alerts – Send notifications to teams
🔹 Store Scan Results – Save reports to a database
🔹 Web UI Dashboard – Visualize findings in a web interface
🔹 Integrate with SIEM – Send alerts to security monitoring systems

📜 License
This project is licensed under the MIT License.

🤝 Contributing
Pull requests are welcome! If you find a bug or want to improve something, feel free to open an issue.

📞 Contact
📧 Security Team: security-team@example.com
🌐 Website: example.com

🚀 Stay secure & automate your defenses! 🔥






