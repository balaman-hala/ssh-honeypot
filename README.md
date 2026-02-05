### 🛡️ SSH Honeypot System

A specialized Docker-based SSH honeypot designed to detect, log, and analyze SSH brute-force attacks and unauthorized access attempts. Perfect for security monitoring and threat intelligence collection.

### ✨ Core Features

- **🔍 SSH-Specific Detection** - Focused exclusively on SSH attack patterns
- **📊 Real-time Monitoring** - Live visualization of SSH attack attempts
- **🗃️ Comprehensive Logging** - JSON-formatted logs with attack metadata
- **🎣 Credential Baiting** - Realistic fake user accounts and passwords
- **📈 Attack Analytics** - IP tracking, frequency analysis, timing patterns

### 🚀 Quick Deployment

### Prerequisites

```bash
# Install required Python package
pip install docker

# Verify Docker is running
docker --version
```

### Start SSH Honeypot

```bash
# Deploy the SSH honeypot container
python main.py --ssh

# Alternative: Start with real-time dashboard
python main.py --ssh --dashboard
```

## 🧪 Testing the Honeypot

### Simulate Attack Attempt

```bash
# Attempt SSH connection with incorrect credentials
ssh admin@localhost -p 2222
Password: wrong123  # Use incorrect password to trigger logging

# Alternative test with different username
ssh root@localhost -p 2222
```

### Quick Test Command

```bash
# Single line test (will fail as expected)
ssh -o ConnectTimeout=5 admin@localhost -p 2222
```

## 📋 Command Reference

| Command                      | Action            | Description                  |
| ---------------------------- | ----------------- | ---------------------------- |
| `python main.py --ssh`       | 🚀 **Deploy**     | Start SSH honeypot container |
| `python main.py --dashboard` | 📊 **Monitor**    | Launch attack dashboard      |
| `python main.py --monitor`   | 👁️ **Background** | Start background monitoring  |
| `python main.py --report`    | 📄 **Analyze**    | Generate attack report       |

## 📁 Project Structure (SSH Focus)

```
honeypot/
├── main.py              # Main controller
├── docker_manager.py    # Docker container management
├── attack_monitor.py    # SSH attack detection
├── bait_creator.py      # Fake SSH credentials
├── containers/
│   ├── Dockerfile.ssh   # SSH honeypot image
│   └── ssh_logger.py    # SSH-specific logging
└── logs/
    ├── ssh_attacks.json # All SSH attack logs
    └── final_report.json# Analysis reports
```

## 🐳 Docker Container

| Container      | Port | Purpose              | Exposed Service |
| -------------- | ---- | -------------------- | --------------- |
| `ssh-honeypot` | 2222 | SSH attack detection | OpenSSH Server  |

## 🔍 Detection Capabilities

### SSH-Specific Attack Patterns:

- **Brute-force attempts** - Multiple password guesses
- **Invalid users** - Non-existent username attempts
- **Connection flooding** - Rapid connection attempts
- **Protocol anomalies** - Non-standard SSH client behavior
- **Credential stuffing** - Common credential combinations

## ⚠️ Security Notes

1. **Real Attack Surface** - This exposes a real SSH service
2. **Network Isolation Recommended** - Use on isolated/VLAN networks
3. **Monitoring Required** - Always monitor logs for suspicious activity
4. **Legal Compliance** - Ensure honeypot use complies with local laws

## 🛠️ Troubleshooting

**No attacks detected?**

```bash
# Trigger a test attack
ssh -o BatchMode=yes -o ConnectTimeout=3 admin@localhost -p 2222
```

**Container won't start?**

```bash
# Check Docker service
docker ps
sudo systemctl restart docker

# Check port availability
netstat -tulpn | grep :2222
```

**Logs not updating?**

```bash
# Check container logs
docker logs ssh-honeypot

# Verify log directory permissions
ls -la logs/
```

## 📊 Expected Output

Successful deployment shows:

```
✅ SSH Honeypot started on port 2222
📊 Dashboard available at http://localhost:8888
📝 Logging to: logs/ssh_attacks.json
🔒 Listening for SSH attacks...
```

## 📄 License

Educational Use - Security Research Tool

```

This version focuses exclusively on the SSH honeypot component. It provides clear SSH-specific deployment, testing, and monitoring instructions while maintaining a professional security tool documentation style.
```
