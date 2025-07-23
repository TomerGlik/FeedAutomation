# Semi-Automation Blacklist Tool 🛡️

This is a Python-based CLI tool designed to help analysts and SOC teams quickly maintain and manage blacklists for hashes, IPs, FQDNs, and ex-employees, with full logging and validation.

The script supports:
- Managing MD5, SHA1, SHA256 file hashes
- Adding, validating and excluding IPv4 addresses and subnets
- Adding FQDNs with validation
- Maintaining an ex-employee list with email generation
- Logging all actions with timestamps and user attribution
- Automatic creation of `.csv` and `.txt` lists for integration into security controls
- Customizable exclusions and validation rules
- Works cross-platform (tested on Windows with PowerShell)

---

## 📂 Features
✅ Hash blacklist (MD5, SHA1, SHA256)  
✅ IPv4 & subnet blacklist with exclusion rules and validation  
✅ FQDN blacklist with validation (no `www.` allowed, only base domain)  
✅ Ex-employee tracking with email auto-generation  
✅ Logging all actions to a `/Logs` directory  
✅ `.gitignore` included to avoid uploading sensitive data  
✅ Friendly CLI with ASCII art banner 😎  

---

## 🚀 Getting Started
### Prerequisites
- Python 3.x
- Works on Windows/Linux/Mac (developed and tested on Windows)
