# InMyMine7 - WordPress Auto Exploit

<div align="center">

![Version](https://img.shields.io/badge/version-0.1-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-Educational-red)
![Status](https://img.shields.io/badge/status-Active-success)

**WordPress Vulnerability Scanner & Exploitation Framework**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [CVEs](#supported-vulnerabilities) • [Support](#contact--support)

</div>

---

A comprehensive WordPress vulnerability scanner and exploitation framework for authorized penetration testing. This tool automatically detects and exploits multiple WordPress security vulnerabilities (CVEs) to help security professionals identify and patch weaknesses.

```
 /$$      /$$                     /$$       /$$             /$$              
| $$$    /$$$                    | $$      |__/            | $$              
| $$$$  /$$$$  /$$$$$$   /$$$$$$ | $$$$$$$  /$$  /$$$$$$$ /$$$$$$    /$$$$$$ 
| $$ $$/$$ $$ /$$__  $$ /$$__  $$| $$__  $$| $$ /$$_____/|_  $$_/   /$$__  $$
| $$  $$$| $$| $$$$$$$$| $$  \ $$| $$  \ $$| $$|  $$$$$$   | $$    | $$  \ $$
| $$\  $ | $$| $$_____/| $$  | $$| $$  | $$| $$ \____  $$  | $$ /$$| $$  | $$
| $$ \/  | $$|  $$$$$$$| $$$$$$$/| $$  | $$| $$ /$$$$$$$/  |  $$$$/|  $$$$$$/
|__/     |__/ \_______/| $$____/ |__/  |__/|__/|_______/    \___/   \______/ 
                       | $$                                             
                       | $$ version 0.1                                                      
                       |__/  
```

## 📋 Table of Contents

- [Legal Disclaimer](#-legal-disclaimer)
- [Features](#features)
- [Screenshots](#screenshots)
- [Supported Vulnerabilities](#supported-vulnerabilities)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Output](#output)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Contact & Support](#contact--support)

## ⚠️ LEGAL DISCLAIMER

**WARNING: This tool is for authorized penetration testing only.** 

This toolkit should only be used on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal and violates the Computer Fraud and Abuse Act (CFAA) and similar laws worldwide. The author assumes no liability for misuse or damage caused by this tool. Users are responsible for ensuring they have proper authorization before running any exploits.

---

## ✨ Features

✅ **Multi-CVE Support** - Exploits 22+ WordPress vulnerabilities across different versions  
✅ **Mass Scanning** - Scan multiple targets simultaneously using thread pooling  
✅ **Single Target Mode** - Focus on individual WordPress installations  
✅ **Automatic Detection** - Identifies vulnerable WordPress plugins and themes  
✅ **Shell Upload** - Uploads web shells for post-exploitation access  
✅ **Credential Management** - Creates admin accounts and captures passwords  
✅ **Result Logging** - Saves shells, credentials, and exploit results  
✅ **Anti-Detection** - Randomized headers, user agents, and request patterns  
✅ **Proxy Support** - Route requests through proxies for anonymity  
✅ **Configuration Management** - Persistent settings via JSON config

## Screenshots

### 🖥️ Main Menu Interface
![Main Menu](images/main-menu.png)

### ⚙️ Exploitation in Progress  
![Exploitation Running](images/exploitation-running.png)

---

## Supported Vulnerabilities

The tool currently exploits the following CVEs:

| No. | CVE ID | Vulnerability Type | Year |
|-----|--------|------------------|------|
| 1 | CVE-2021-25094 | WordPress Plugin Vulnerability | 2021 |
| 2 | CVE-2023-5360 | Arbitrary File Upload | 2023 |
| 3 | CVE-2024-2667 | Authentication Bypass | 2024 |
| 4 | CVE-2024-9234 | Remote Code Execution | 2024 |
| 5 | CVE-2024-56064 | SQL Injection | 2024 |
| 6 | CVE-2025-4334 | CSRF Token Bypass | 2025 |
| 7 | CVE-2025-4606 | Privilege Escalation | 2025 |
| 8 | CVE-2025-5394 | Unauthenticated File Upload | 2025 |
| 9 | CVE-2025-6389 | Admin Panel Bypass | 2025 |
| 10 | CVE-2025-6440 | Cross-Site Request Forgery | 2025 |
| 11 | CVE-2025-6934 | Remote File Inclusion | 2025 |
| 12 | CVE-2025-7441 | SQL Injection | 2025 |
| 13 | CVE-2025-7852 | Authentication Bypass | 2025 |
| 14 | CVE-2025-13374 | Arbitrary File Upload | 2025 |
| 15 | CVE-2025-15403 | User Enumeration | 2025 |
| 16 | CVE-2025-29009 | Object Injection | 2025 |
| 17 | CVE-2025-47539 | Permission Escalation | 2025 |
| 18 | CVE-2025-48148 | Insecure Deserialization | 2025 |
| 19 | CVE-2026-0740 | Plugin Vulnerability | 2026 |
| 20 | CVE-2026-0920 | Theme Vulnerability | 2026 |
| 21 | CVE-2026-1357 | Admin Enumeration | 2026 |
| 22 | CVE-2026-3891 | Backdoor Installation | 2026 |

## Requirements

- **Python 3.8+** or newer
- **Required Python Packages:**
  - `requests` - HTTP client library
  - `urllib3` - HTTP client with connection pooling
  - `beautifulsoup4` - HTML/XML parsing
  - `colorama` - Cross-platform colored terminal output
  - `pycryptodome` - AES payload encryption (CVE-2026-1357)

## 🚀 Quick Start

```bash
# 1. Clone repository
git clone https://github.com/InMyMine7/Mephisto
cd Mephisto

# 2. Install dependencies
pip install -r requirements.txt

# 3. Verify payload files are present
ls assets/payloads
# inmymine-shell.jpg and mem.zip ship with the repository

# 4. Run the tool
python main.py
```

## Installation

### Prerequisites

Before starting, ensure you have:
- Python 3.8 or higher installed
- Git installed
- Internet connection for downloading dependencies
- At least 100MB free disk space

---

### 🪟 Windows Installation

#### Step 1: Install Python
1. Download Python from [python.org](https://www.python.org/downloads/)
2. During installation, **check "Add Python to PATH"**
3. Click "Install Now"
4. Verify installation:
```bash
python --version
```

#### Step 2: Install Git (Optional but Recommended)
1. Download from [git-scm.com](https://git-scm.com/download/win)
2. Run installer and follow prompts
3. Verify installation:
```bash
git --version
```

#### Step 3: Clone Repository
**Option A: Using Git (Recommended)**
```bash
git clone https://github.com/InMyMine7/Mephisto
cd Mephisto
```

**Option B: Manual Download**
1. Visit [GitHub Repository](https://github.com/InMyMine7/InMyMine7)
2. Click "Code" → "Download ZIP"
3. Extract ZIP file
4. Open command prompt in extracted folder

#### Step 4: Install Dependencies
```bash
pip install -r requirements.txt
```

#### Step 5: Prepare Payload Files
```bash
ls assets/payloads
# inmymine-shell.jpg and mem.zip ship with the repository
```

#### Step 6: Run the Tool
```bash
python main.py
```

---

### 🐧 Linux Installation

#### Step 1: Update System
**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt upgrade -y
```

**Fedora/RHEL:**
```bash
sudo dnf update -y
```

**Arch Linux:**
```bash
sudo pacman -Syu
```

#### Step 2: Install Python & Dependencies
**Ubuntu/Debian:**
```bash
sudo apt install -y python3 python3-pip python3-venv git
```

**Fedora/RHEL:**
```bash
sudo dnf install -y python3 python3-pip git
```

**Arch Linux:**
```bash
sudo pacman -S python python-pip git
```

#### Step 3: Verify Installation
```bash
python3 --version
pip3 --version
git --version
```

#### Step 4: Clone Repository
```bash
git clone https://github.com/InMyMine7/Mephisto
cd Mephisto
```

#### Step 5: Create Virtual Environment (Recommended)
```bash
python3 -m venv venv
source venv/bin/activate  # On Linux
```

#### Step 6: Install Python Dependencies
```bash
pip install -r requirements.txt
```

#### Step 7: Prepare Payload Files
```bash
# Payloads ship in assets/payloads/ - no copy needed
chmod +x main.py  # Make script executable
```

#### Step 8: Run the Tool
```bash
python3 main.py
```

---

### 🍎 macOS Installation

#### Step 1: Install Homebrew (if not installed)
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### Step 2: Install Python & Dependencies
```bash
brew install python@3.11 git
```

#### Step 3: Verify Installation
```bash
python3 --version
pip3 --version
git --version
```

#### Step 4: Clone Repository
```bash
git clone https://github.com/InMyMine7/Mephisto
cd Mephisto
```

#### Step 5: Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

#### Step 6: Install Dependencies
```bash
pip install -r requirements.txt
```

#### Step 7: Prepare Payload Files
```bash
# Payloads ship in assets/payloads/ - no copy needed
chmod +x main.py
```

#### Step 8: Run the Tool
```bash
python3 main.py
```

---

### 🐳 Docker Installation (Optional)

If you prefer using Docker:

**Create a Dockerfile:**
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "main.py"]
```

**Build and Run:**
```bash
docker build -t inmymine7 .
docker run -it -v $(pwd)/Result:/app/Result inmymine7
```

---

### Troubleshooting Installation

| Issue | Solution |
|-------|----------|
| **"python: command not found"** | Make sure Python is in PATH, or use `python3` |
| **"Permission denied" on Linux** | Run `chmod +x main.py` |
| **"pip: command not found"** | Use `pip3` instead of `pip` |
| **Module import errors** | Run `pip install -r requirements.txt --force-reinstall` |
| **No module named 'mephisto'** | Make sure you're in the Mephisto directory (the one containing `main.py`) |

---

### 1. Clone the Repository
```bash
git clone https://github.com/InMyMine7/Mephisto
cd Mephisto
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Prepare Required Files
Payload files live in `assets/payloads/` and ship with the repository:
```bash
ls assets/payloads
# inmymine-shell.jpg  mem.zip
```

If a file is missing, drop it into `assets/payloads/` before running the tool.

## ⚙️ Configuration

Edit `config.json` to customize the tool's behavior:

```json
{
    "TIMEOUT": 10,                          // Request timeout in seconds
    "UPLOAD_TIMEOUT": 15,                   // File upload timeout
    "FILES_DIR": "assets/payloads",         // Directory containing payloads
    "REQUIRED_FILES": [                     // Files required for exploitation
        "inmymine-shell.jpg",
        "mem.zip"
    ],
    "RESULT_DIR": "Result",                 // Output directory for results
    "SHELLS_FILE": "Shells.txt",            // Log file for uploaded shells
    "PASSWORDS_FILE": "password_change.txt", // Log file for changed passwords
    "ADMINS_FILE": "wp-admin.txt",          // Log file for admin accounts
    "REGISTER_FILE": "wp-register.txt",     // Log file for registrations
    "PROXIES": [],                          // Optional outbound proxy list
    "DISABLED_EXPLOITS": [],                // CVE ids to skip during discovery
    "UPDATE_URL": "https://...",            // URL for version updates
    "SUPPORT_URL": ["https://..."],         // Support/donation links
    "EMAIL": "default@example.com"          // Default email for operations
}
```

Paths are resolved against the project root, so the tool runs correctly no
matter which directory you launch it from.

## 💻 Usage

### Run the Application
```bash
python main.py
```

### Main Menu Options

```
  [1] Start exploit        single target or a target list
  [2] List exploits        22 CVE modules registered
  [3] Support developer    keep the project alive
  [0] Exit
```

#### 🎯 Option 1: Start Exploit

Pick `[1]` for a single target or `[2]` for a target list file, then answer:

```
→ target url https://target-wordpress.com
→ per-exploit deadline in seconds (blank = none)
```

Mass scans also ask for a thread count. Each exploit is drawn as it finishes:

```
  → http://target/  22 exploits
  ────────────────────────────────────────────────
   1/22  CVE-2021-25094    VULN      █░░░░░░░░░░░   0.61s
   2/22  CVE-2023-5360     clean     ██░░░░░░░░░░   0.78s
  ...
  ────────────────────────────────────────────────
```

followed by a verdict table, a findings table and the path to the result files.

#### ✅ Option 2: List Exploits
Shows every registered CVE with its type and affected component.

#### 💰 Option 3: Support Developer
Displays links for supporting the development of this tool.

### 🖥️ Terminal Behaviour

| Flag / variable | Effect |
|---|---|
| `python main.py <url\|list> [more…]` | Headless scan without menus; prints the same summary |
| `python main.py -v` / `--verbose` | Show each exploit's per-request log lines |
| `MEPHISTO_ASCII=1` | Force plain-ASCII borders (older Windows consoles) |

The UI switches the Windows console to UTF-8 on start when box drawing is
available and falls back to ASCII automatically when it is not. `Ctrl+C` during
a scan returns to the menu instead of closing the tool.

### 📋 Input File Format (Mass Scanning)

Create a `targets.txt` file with one URL per line:
```
https://wordpress-site1.com
https://wordpress-site2.com
https://wordpress-site3.com
```

Lines starting with `#` are ignored. Then run the tool and select option 1 for
mass scanning, providing the file path when prompted.

## 📊 Output

Results are stored in the `Result/` directory:

| File | Description |
|------|-------------|
| 📄 **Shells.txt** | Uploaded web shell URLs and access credentials |
| 🔐 **password_change.txt** | Modified admin passwords |
| 👤 **wp-admin.txt** | Created admin accounts |
| 📝 **wp-register.txt** | Registered user accounts |

Each line contains the target URL and relevant exploitation data in CSV format.

## 🛡️ Anti-Detection Features

The tool includes several evasion techniques to avoid detection:

| Feature | Description |
|---------|-------------|
| 🔀 **Randomized User Agents** | 8 different browser identifications |
| 📋 **Random Headers** | Varies HTTP headers per request |
| 🍪 **Randomized Cookies** | Generates unique session identifiers |
| ⏱️ **Request Delays** | Implements random delays between requests |
| 🌐 **Browser Simulation** | Mimics legitimate browser navigation patterns |
| 🔗 **Proxy Support** | Routes traffic through proxy servers |
| 🗣️ **Accept-Language Rotation** | Uses multiple language preferences |
| 🔄 **Referer Randomization** | Varies referrer headers |

## 📊 Logging

All operations are logged with color-coded output:
- 🟢 **Green [+]** - Successful exploitation
- 🔴 **Red [-]** - Failed attempt  
- ⚠️ **Red [!]** - Error or warning

## 📁 Project Structure

```
Mephisto/
├── main.py                  # Entry point (delegates to mephisto.cli)
├── config.json              # Runtime configuration
├── requirements.txt         # Python dependencies
├── README.md                # This file
│
├── mephisto/                # Core package
│   ├── __init__.py          # Public exports
│   ├── cli.py               # Menus, prompts, scan flow, headless mode
│   ├── ui.py                # Banner, tables, panels, progress bars
│   ├── engine.py            # Target runner, per-exploit isolation & verdicts
│   ├── client.py            # Exploit instance handed to every module
│   ├── config.py            # config.json loading and path resolution
│   ├── registry.py          # Auto-discovers exploits/cve_*.py
│   └── results.py           # Result file tracking (artifact detection)
│
├── exploits/                # One file per CVE - auto-discovered
│   ├── __init__.py
│   ├── _template.py         # Copy this to add a new CVE
│   ├── cve_2021_25094.py
│   ├── cve_2023_5360.py
│   └── ... (22 modules)
│
├── assets/
│   └── payloads/            # Upload payloads
│       ├── inmymine-shell.jpg
│       └── mem.zip
│
├── tests/
│   └── test_core.py         # Registry, client, engine, UI, config self-checks
│
├── docs/
│   └── ADDING_CVE.md        # How to add a CVE module
│
└── Result/                  # Output directory (created at runtime)
    ├── Shells.txt
    ├── password_change.txt
    ├── wp-admin.txt
    └── wp-register.txt
```

### How an exploit runs

1. `mephisto.registry.discover()` imports every `exploits/cve_*.py` and reads its
   entry point, so there is no central list to keep in sync.
2. `mephisto.engine.run_target()` builds one `Exploit` instance per target and
   calls each module in turn.
3. A module records findings with `exploit_instance.record(kind, value)`.
4. The engine compares result-file line counts before and after each module, so
   a target is marked `VULN` only when something was actually recorded.
5. A module that raises is logged as an error and the scan continues.

## 🔧 Advanced Usage

### 🔗 Using with Proxies

Add proxies to `config.json`:

```json
{
    "PROXIES": [
        "http://proxy1.com:8080",
        "http://proxy2.com:8080",
        "http://proxy3.com:8080"
    ]
}
```

The tool randomly selects from the list for each target, improving anonymity.

### 🛠️ Customizing Exploits

Drop a new module into `exploits/` — it is picked up automatically on the next
run:

```bash
cp exploits/_template.py exploits/cve_2026_4444.py
$EDITOR exploits/cve_2026_4444.py
python -m unittest discover -s tests -t .   # verify discovery + entry point
```

See [docs/ADDING_CVE.md](docs/ADDING_CVE.md) for the module contract, metadata
fields and result-recording rules. To skip a module without deleting it, list
its CVE id in `DISABLED_EXPLOITS`.

### ✅ Running the Self-Checks

```bash
python -m unittest discover -s tests -t .
```

The suite covers module discovery, URL normalisation, request helpers, result
recording, per-exploit verdicts and config path resolution. It needs no network
access and no target.

### ⚡ Rate Limiting

Adjust the threading/pooling count to control request rate:

```bash
[~] Enter number of threads (default 10): 1  # For slower, stealthier scans
[~] Enter number of threads (default 10): 50 # For faster, aggressive scans
```

**Recommended Values:**
- `1-5`: Stealth mode (slow but undetectable)
- `10-20`: Balanced mode (normal speed)
- `20+`: Aggressive mode (fast but may trigger IDS/WAF)

## Troubleshooting

### ❌ "File not found" Error
**Problem:** Tool complains about missing files  
**Solution:** Ensure `inmymine-shell.jpg` and `mem.zip` are in `assets/payloads/`.

### ⏱️ Connection Timeout
**Problem:** Requests are timing out  
**Solutions:**
- Increase `TIMEOUT` value in `config.json`
- Check your internet connection
- Verify the target URL is correct
- Try reducing number of threads

### 📦 Import Errors
**Problem:** Missing Python modules  
**Solution:** Reinstall dependencies:
```bash
pip install -r requirements.txt --force-reinstall
```

### 💾 Results Not Saving
**Problem:** Output files not being created  
**Solution:** Ensure the `Result/` directory exists with write permissions:
```bash
mkdir -p Result
chmod 755 Result
```

## ❓ Frequently Asked Questions (FAQ)

**Q: Is this tool legal?**  
A: This tool is for authorized penetration testing only. Ensure you have explicit written permission before testing any system.

**Q: Can I use this against any WordPress site?**  
A: Only use this against systems you own or have written permission to test. Unauthorized access is illegal.

**Q: How do I avoid detection?**  
A: Use proxies, adjust thread count, and enable anti-detection features. See [Anti-Detection Features](#anti-detection-features).

**Q: Why are my exploits failing?**  
A: Check if the WordPress version is vulnerable, ensure required files are present, and verify network connectivity.

**Q: Can I add new CVEs?**  
A: Yes. Copy `exploits/_template.py` to `exploits/cve_<year>_<number>.py`, implement the entry point, and record findings with `exploit_instance.record(...)`. Discovery is automatic - there is no registry to edit. See [docs/ADDING_CVE.md](docs/ADDING_CVE.md).

**Q: What's the difference between single and mass scanning?**  
A: Single mode tests one target, mass mode processes multiple targets from a file using thread pools.

## Performance Tips

1. **Threading** - Start with 10 threads, increase for faster scanning
2. **Timeouts** - Reduce timeouts for faster failure detection
3. **Batch Size** - For mass scanning, process targets in groups
4. **Network** - Use local network for faster, more reliable exploits

## Version History

| Version | Date | Changes |
|---------|------|---------|
| **v0.1** | 2026-05-01 | Initial release with 22+ WordPress CVE exploits |
| **v0.2** | 2026-11-01 | Restructured into a package: auto-discovered `exploits/`, per-exploit isolation and verdicts, config-driven proxies/disabled list, self-check suite |

## 📞 Contact & Support

<div align="center">

[![GitHub](https://img.shields.io/badge/GitHub-InMyMine7-black?style=for-the-badge&logo=github)](https://github.com/InMyMine7)
[![Telegram](https://img.shields.io/badge/Telegram-@InMyMineee-blue?style=for-the-badge&logo=telegram)](https://t.me/InMyMineee)

**Have questions or want to support development? Reach out!**

</div>

## 🤝 Contributing

Contributions are welcome! To add new exploits or improve existing ones:

1. **Fork** the repository
2. **Create** a new module in `exploits/`
3. **Follow** the naming convention: `cve_<year>_<number>.py` (drives the CVE id)
4. **Run** the self-checks: `python -m unittest discover -s tests -t .`
5. **Test** the module against a lab target you control
6. **Submit** your PR with a clear description

### Contribution Guidelines
- Write clean, documented code
- Include error handling
- Test all functionality
- Update README if adding new features

## 📜 License

This project is provided for **educational and authorized security testing purposes only**. 

Users are solely responsible for ensuring they have proper authorization before testing any systems. The author assumes **NO LIABILITY** for any misuse, damage, or illegal activities.

## ⚠️ Legal Disclaimer

**This tool should ONLY be used for:**
- ✅ Authorized penetration testing
- ✅ Security research on owned systems
- ✅ Educational purposes with proper permissions

**NOT for:**
- ❌ Unauthorized system access
- ❌ Illegal hacking activities
- ❌ Damage to systems without permission

By using this tool, you acknowledge that you understand and accept these terms.

---

<div align="center">

**Made with ❤️ by InMyMine7**  
*Disclaimer: This tool is for authorized testing only. Unauthorized access is illegal.*

</div>
