# Semi-Automation Blacklist Tool 🛡️

A Python-based CLI tool for SOC teams and analysts to manage blacklists of hashes, IPs, FQDNs, and ex-employees, with logging, validation, and automation.

## 📂 Features Overview

| Feature                        | Description                                                   |
|--------------------------------|---------------------------------------------------------------|
| 🔗 Hash Blacklist              | Manage MD5, SHA1, SHA256 with validation & deduplication     |
| 🌐 IP & Subnet Blacklist       | Add/validate IPv4 & subnets, with exclusion rules & subnet policies |
| 🖥️ OT & M365 Security          | Supports OT networks & Microsoft 365 security compliance     |
| 🖋️ FQDN Blacklist              | Add/validate fully-qualified domains with syntax checks      |
| 👤 Ex-Employee Tracker         | Manage ex-employees with auto-generated emails              |
| 📝 Logging                     | Logs all actions with timestamp & username                  |
| 📊 Dashboards & Playbooks      | Builds SIEM dashboards & IR playbooks (in code logic)        |
| 🪄 Automation                  | Automates workflows with Python, Bash, PowerShell           |

## 🧪 Validation Rules

| Entity         | Validation Logic                                                                 |
|----------------|-----------------------------------------------------------------------------------|
| MD5            | Exactly 32 hexadecimal characters                                                |
| SHA1           | Exactly 40 hexadecimal characters                                                |
| SHA256         | Exactly 64 hexadecimal characters                                                |
| IPv4 Address   | Must be valid IPv4, cannot be private (e.g., 192.168.x.x, 10.x.x.x, 172.16.x.x)  |
| Subnet         | CIDR format (e.g., `192.168.1.0/24`), valid base IP and mask                     |
| FQDN           | Cannot start with `www.`, must match standard FQDN rules (RFC-compliant):        |
|                | - Total length ≤ 253                                                             |
|                | - No consecutive dots or hyphens                                                 |
|                | - Each label ≤ 63 characters, letters/digits/hyphens only, no trailing hyphen    |
| Ex-Employee    | Must be in `First.Last` format, alphabetic, ≥2 chars per part                    |

## 📁 Output Files & Folders

| File/Folder                | Purpose                            |
|-----------------------------|------------------------------------|
| `Logs/`                     | Logs of all actions taken         |
| `*.txt`                     | Plain text blacklists (IPs, hashes, etc.) |
| `*.csv`                     | CSV-formatted blacklists          |
| `excluded_ips.txt`          | List of IPs/subnets excluded by policy |
| `C:\inetpub\wwwroot\feeder` | Ex-employee CSV list (if applicable) |

### 📋 Prerequisites

- Python 3.x
- Tested on Windows, should work on Linux/Mac

### 💻 Commands Summary

| Command | Action                                   |
| ------- | ---------------------------------------- |
| `F`     | Add a file hash (MD5/SHA1/SHA256)        |
| `I`     | Add a single IPv4 or subnet              |
| `M`     | Add multiple IPs (comma/space separated) |
| `E`     | Add an ex-employee                       |
| `U`     | Add a FQDN                               |
| `S`     | Search if IP exists in blacklist         |
| `C`     | Add an IP to exclusion list              |
| `X`     | Exit                                     |


### 👨‍💻 Development Notes

All validations implemented using regex & Python standard library (ipaddress for IPs & subnets).

Logging done to Logs/ folder with timestamps and username.

ASCII art banner included — because why not? 😎

.gitignore excludes sensitive .txt, .csv, and Logs/ folder

### 🙋‍♂️ Author

Made by Tomer Glik
