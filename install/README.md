# Security One IDS Agent - Desktop Installation

Quick installation scripts for personal computers.

## 🪟 Windows Installation

**Run in PowerShell as Administrator:**

```powershell
# Download and run installer
iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/vito1317/security-one-ids/main/install/install-windows.ps1'))
```

**Or with parameters:**
```powershell
.\install-windows.ps1 -WafHubUrl "https://waf.example.com" -AgentToken "your-token"
```

## 🍎 macOS / 🐧 Linux Installation

**One-line install:**

```bash
curl -fsSL https://raw.githubusercontent.com/vito1317/security-one-ids/main/install/install.sh | sudo bash
```

**Or with environment variables:**
```bash
WAF_HUB_URL="https://waf.example.com" AGENT_TOKEN="your-token" sudo -E bash install.sh
```

## 📋 Requirements

| Platform | Requirements |
|----------|-------------|
| Windows | Windows 10+, PowerShell 5.1+ |
| macOS | macOS 10.15+, Homebrew (auto-installed) |
| Linux | Debian/Ubuntu or RHEL/CentOS |

## 🔧 After Installation

```bash
# Quick scan
ids-scan

# Full AI analysis
ids-scan --full

# Check service status
ids-status
```

## 📁 Installation Paths

| Platform | Install Path | Logs |
|----------|-------------|------|
| Windows | `C:\Program Files\SecurityOneIDS` | `C:\ProgramData\SecurityOneIDS\logs` |
| macOS/Linux | `/opt/security-one-ids` | `/var/log/security-one-ids` |
