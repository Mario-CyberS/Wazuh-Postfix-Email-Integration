# Wazuh Postfix Email Integration  
This project documents the integration of **Wazuh** with **Postfix** and a custom **Python** script to send real-time security alerts via Gmail SMTP, allowing structured, secure, and reliable email notifications directly from your SIEM server.

---

## 🎯 Objective  
To configure a Postfix mail relay on the Wazuh server and use a Python integration script to send customized email alerts for high-priority Wazuh events (e.g., level 12+), formatted for readability and tailored for multi-environment monitoring.

---

## 🔍 Why Use Postfix with Wazuh?  
Email integration gives SOC teams:
- Direct delivery of critical alerts to inboxes  
- Custom subject lines and email formatting  
- Secure Gmail SMTP relay with TLS  
- Visibility across environments using unique identifiers per alert  
- Logging and debugging of email activity

---

## 📚 Skills Learned  
- Installing and configuring Postfix on Linux  
- Creating a secure Gmail SMTP relay  
- Writing a custom Python integration script  
- Sending, logging, and testing SIEM alerts via email

---

## 🛠️ Tools Used  
<div>
  <img src="https://img.shields.io/badge/-Wazuh-0078D4?&style=for-the-badge&logo=Wazuh&logoColor=white" />
  <img src="https://img.shields.io/badge/-Postfix-CC0033?&style=for-the-badge&logo=Gmail&logoColor=white" />
  <img src="https://img.shields.io/badge/-Python-3776AB?&style=for-the-badge&logo=Python&logoColor=white" />
  <img src="https://img.shields.io/badge/-Linux-FCC624?&style=for-the-badge&logo=Linux&logoColor=black" />
</div>

---

## 📝 Deployment Steps  

### 1. Install Postfix and Dependencies
```bash
sudo dnf install postfix cyrus-sasl cyrus-sasl-plain mailx -y
sudo systemctl enable postfix
sudo systemctl start postfix
```
### 2. Configure Postfix
Open the Postfix configuration file:
```bash
sudo nano /etc/postfix/main.cf
```
Modify or add the following lines, they are scattered and might be on/in there already:
```bash
relayhost = [smtp.gmail.com]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_CAfile = /etc/pki/tls/certs/ca-bundle.crt
smtp_use_tls = yes
compatibility_level = 2
```
### 3. Configure SMTP Authentication for your email
```bash
echo "[smtp.gmail.com]:587 "fromEmail@email.com:pass" | sudo tee /etc/postfix/sasl_passwd > /dev/null
```
Replace “pass” with real pass
Convert it into a Postfix-readable format:
```bash
sudo postmap /etc/postfix/sasl_passwd
```
Secure the file:
```bash
sudo chmod 400 /etc/postfix/sasl_passwd
sudo chown root:root /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
sudo chmod 0600 /etc/postfix/sasl_passwd /etc/postfix/sasl_passwd.db
```
### 4. Restart Postfix
```bash
sudo systemctl restart postfix
```
### 5. Test Postfix Configuration
Send a test email to ToEmail@email.com, or replace this email with your personal secure Company email for testing:
```bash
echo "Hi! We are testing Postfix!" | mail -s "Test Postfix" ToEmail@email.com
```
Check for any errors in the logs:
```bash
sudo tail -f /var/log/maillog
```
You should see a line like this if it properly sent, “status=sent”:
```bash
Feb 18 13:30:34 wazuh postfix/smtp[2408368]: 3CA2D6F4C: to=<ToEmail@email.com>, relay=smtp.gmail.com[142.250.113.109]:587, delay=1.2, delays=0.02/0.22/0.26/0.69, dsn=2.0.0, status=sent (250 2.0.0 OK  1739903434 586e51a60fabf-2b954820707sm5087865fac.10 - gsmtp)
```
### 6. Configure Wazuh ossec.conf
Configure Wazuh ossec.conf to ensure that default email alerting is turned off, we wont need this since we will be using a custom email python script for forwarding the emailed alerts, this way we can customize subject headers and the structure of the email.
Edit the Wazuh configuration file:
```bash
sudo nano /var/ossec/etc/ossec.conf
```
Add the following configuration, <email_notification> should be set to no, this should be set off as default:
```bash
<global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>yes</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>localhost</smtp_server>
    <email_from>FromEmail@email.com</email_from>
    <email_to>ToEmail@email.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <agents_disconnection_time>10m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
    <update_check>yes</update_check>
  </global>
```
Restart the Wazuh manager:
```bash
sudo systemctl restart wazuh-manager
```
### 7. Add a Custom Subject Header
Now lets add a custom subject header to differentiate this SITE Wazuh server with our other wazuh servers using the same emails for emailed alerts. As a solution we will use a custom py script to email out alerts.
Install Python on Wazuh box:
```bash
sudo dnf install -y epel-release
sudo dnf module enable -y python39
sudo dnf install -y python39 python39-pip
pip3 install requests
python3 --version
pip3 --version
```
Create a custom python mail script in the ossec integrations dir:
```bash
sudo nano /var/ossec/integrations/custom-email.py
```
```bash
#!/usr/bin/env python3
import sys
import json
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
from datetime import datetime
# === Configuration ===
SMTP_SERVER = '127.0.0.1'
SMTP_PORT = 25
SENDER_EMAIL = 'FromEmail@email.com'
RECEIVER_EMAIL = 'ToEmail@email.com'
LOG_FILE = '/var/ossec/logs/custom-email_integration.log'
logging.basicConfig(
    filename=LOG_FILE,
    filemode='a',
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S',
    level=logging.INFO
)
# === Read Alert from STDIN or File (fallback) ===
try:
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r') as f:
            alert_json = json.load(f)
    else:
        alert_input = sys.stdin.read().strip()
        alert_json = json.loads(alert_input)
    logging.info("Alert loaded successfully.")
except Exception as e:
    logging.error(f"Failed to load alert: {str(e)}")
    sys.exit(1)
# === Extract Fields ===
try:
    timestamp = alert_json.get('timestamp', 'N/A')
    location = alert_json.get('location', 'N/A')
    rule = alert_json.get('rule', {})
    rule_id = rule.get('id', 'N/A')
    rule_level = rule.get('level', 'N/A')
    description = rule.get('description', 'N/A')
    agent = alert_json.get('agent', {})
    agent_id = agent.get('id', 'N/A')
    agent_name = agent.get('name', 'N/A')
    full_log = alert_json.get('full_log', 'N/A')
    logging.info("Extracted alert fields.")
except Exception as e:
    logging.error(f"Error extracting fields: {str(e)}")
    sys.exit(1)
# === Construct Email ===
try:
    subject = f"[Wazuh SITE Alert] Level {rule_level} - Rule {rule_id}: {description}"
    body = f"""
Wazuh [SITE] Alert Notification
Time:           {timestamp}
Location:       {location}
Rule ID:        {rule_id}
Rule Level:     {rule_level}
Description:    {description}
Agent:          {agent_name} (ID: {agent_id})
Log Entry:
{full_log}
-- End of Notification --
"""
    msg = MIMEMultipart()
    msg['From'] = f"Wazuh <{SENDER_EMAIL}>"
    msg['To'] = RECEIVER_EMAIL
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.send_message(msg)
    logging.info("Email sent successfully.")
except Exception as e:
    logging.error(f"Failed to send email: {str(e)}")
    sys.exit(1)
```
Set the permissions for the script:
```bash
sudo chown root:wazuh /var/ossec/integrations/custom-email.py
sudo chmod 750 /var/ossec/integrations/custom-email.py
```
Create the .log file for these emailed alerts, then set permissions for it as well:
```bash
sudo touch /var/ossec/logs/custom-email_integration.log
```
```bash
sudo chown root:wazuh /var/ossec/logs/custom-email_integration.log
sudo chmod 664 /var/ossec/logs/custom-email_integration.log
```
Configure the Integration in Wazuh, add this below the default email block:
```bash
sudo nano /var/ossec/etc/ossec.conf
```
```bash
  <integration>
    <name>custom-email.py</name>
    <level>12</level>
    <alert_format>json</alert_format>
    <options>JSON</options>
  </integration>
```
Restart the Wazuh Manager, for changes to take affect:
```bash
sudo systemctl restart wazuh-manager
```
### 8. Verify Wazuh Email Alerts
- Trigger an alert in Wazuh that matches the specified rule ID or severity level. Or lower the level on the config block to like 10 to see if some alerts get emailed. Recommend using your own personal secure DCI email first to test, as to not blast a lot of emails to an already noisy group email.
- Check the email inbox for the Wazuh email alerts. You can insert your secure email in the script for testing until its all working good then put the proper email in the script.
Monitor Wazuh logs for any issues:
```bash
sudo tail -f /var/ossec/logs/ossec.log
```
---

## 👨‍💻 Author  
Mario Tagaras | Cybersecurity Engineer | Florida State University Alum  







