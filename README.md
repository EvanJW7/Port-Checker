# Port Checker - Network Security Monitoring Tool

A comprehensive bash script that monitors your system for potential security vulnerabilities by checking listening ports, remote management settings, and common security risks.

## 🛡️ What It Does

The Port Checker script performs a thorough security audit of your macOS system by monitoring:

- **🔍 Listening Ports** - All active network connections
- **🛡️ Remote Management** - Remote login and management services
- **📦 Dropbox LAN Sync** - Local network file sharing
- **🔥 Firewall Status** - macOS firewall configuration
- **☕ Java Processes** - Java applications with network access

## 🚀 Features

### Security Checks
- **Port Monitoring** - Identifies all listening ports and their associated processes
- **Remote Access Detection** - Checks for enabled remote login services
- **Dropbox LAN Sync** - Detects local network file sharing (potential security risk)
- **Firewall Status** - Verifies if macOS firewall is enabled
- **Java Process Monitoring** - Identifies Java applications with network access

### Smart Analysis
- **Risk Assessment** - Provides overall security assessment
- **Actionable Recommendations** - Suggests specific steps to improve security
- **Clear Warnings** - Highlights potential security concerns
- **Detailed Reporting** - Comprehensive output with explanations

## 📦 Installation

### Prerequisites
- macOS (tested on macOS 10.15+)
- Bash shell
- Administrator privileges (for some checks)

### Quick Setup
```bash
# Clone or download the script
git clone <your-repo-url>
cd port-checker

# Make the script executable
chmod +x port_checker.sh

# Run the script
./port_checker.sh
```

## 🎯 Usage

### Basic Usage
```bash
# Run the security check
./port_checker.sh
```

### Example Output
```
===== PORT WATCHDOG REPORT =====

🔍 Listening Ports:
COMMAND  PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
launchd  1       root   12u  IPv6 0x1234567890123456      0t0  TCP *:22 (LISTEN)
launchd  1       root   13u  IPv4 0x1234567890123456      0t0  TCP *:22 (LISTEN)

🛡️ Remote Management Check:
✅ 'remoted' not running

📦 Dropbox LAN Sync Check:
✅ Dropbox LAN sync ports not open

🔥 Firewall Status:
✅ Firewall is ON

☕ Java Listening Check:
✅ No Java processes listening on ports

===== END OF REPORT =====

🔒 OVERALL SAFETY ASSESSMENT:
✅  System appears secure. No obvious security issues found.
```

## 🔍 Security Checks Explained

### 1. Listening Ports
- **What it checks**: All active network connections and listening ports
- **Why it matters**: Open ports can be entry points for unauthorized access
- **Risk level**: Medium - depends on what's listening

### 2. Remote Management
- **What it checks**: Remote login and management services
- **Why it matters**: Remote access can be exploited if not properly secured
- **Risk level**: High - if enabled without proper security

### 3. Dropbox LAN Sync
- **What it checks**: Dropbox local network file sharing (ports 17500, 17600, 17603)
- **Why it matters**: Can expose files to other devices on your network
- **Risk level**: Medium - depends on network security

### 4. Firewall Status
- **What it checks**: macOS firewall configuration
- **Why it matters**: Firewall blocks unauthorized network access
- **Risk level**: High - if disabled

### 5. Java Processes
- **What it checks**: Java applications with network access
- **Why it matters**: Java can have security vulnerabilities
- **Risk level**: Medium - depends on the application

## 🔧 Troubleshooting

### Common Issues

**"Permission denied" errors**
- Run with sudo: `sudo ./port_checker.sh`
- Check file permissions: `chmod +x port_checker.sh`

**Script not found**
- Ensure you're in the correct directory
- Check if the script is executable: `ls -la port_checker.sh`

**No output**
- Check if you have the required permissions
- Verify bash is available: `which bash`

## 🛠️ Customization

### Modifying Port Checks
Edit the script to add or remove specific port checks:

```bash
# Add a new port check
if lsof -iTCP:8080 -sTCP:LISTEN >/dev/null; then
  echo "⚠️ Port 8080 is open"
fi
```

### Adding New Security Checks
Extend the script with additional security checks:

```bash
# Example: Check for SSH connections
echo "🔐 SSH Connections:"
ssh_connections=$(lsof -i :22 | grep ESTABLISHED)
if [[ -n "$ssh_connections" ]]; then
  echo "⚠️ Active SSH connections found:"
  echo "$ssh_connections"
else
  echo "✅ No active SSH connections"
fi
```

## 📊 Output Interpretation

### ✅ Safe Indicators
- No listening ports (except system services)
- Remote login disabled
- Firewall enabled
- No unnecessary network services

### ⚠️ Warning Indicators
- Unusual listening ports
- Remote login enabled
- Dropbox LAN sync active
- Firewall disabled
- Java processes with network access

### 🔴 High Risk Indicators
- Multiple unknown listening ports
- Remote login enabled on public networks
- Firewall completely disabled
- Suspicious network activity

## 🤝 Contributing

Feel free to submit issues, feature requests, or pull requests to improve the script!

### Suggested Improvements
- Add support for Linux systems
- Include more detailed process information
- Add network traffic analysis
- Create a GUI version
- Add automated remediation suggestions

## 📄 License

This project is open source and available under the MIT License.

## ⚠️ Disclaimer

This script is for educational and security auditing purposes. Always:
- Run in a controlled environment
- Understand what each check does
- Review results carefully
- Follow security best practices
- Consult with security professionals for critical systems

---

**🔒 Stay secure, stay informed!**
