# 🚨 Docker Honeypot System

A real honeypot system that detects and logs SSH brute-force attacks using Docker containers.

## 📋 Features

- ✅ **Real SSH Honeypot** - Detects actual attack attempts
- ✅ **Real-time Dashboard** - Shows attacks as they happen
- ✅ **JSON Logging** - All attacks saved in structured format
- ✅ **Statistics** - Attack counts, unique IPs, trends
- ✅ **Bait Files** - Fake credentials to attract attackers

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install docker
```

### 2. Start All Honeypots

```bash
python main.py --all
```

### 3. View Real-time Dashboard

```bash
python main.py --dashboard
```

## 🔧 Manual Testing

### Test SSH Honeypot (use WRONG password):

```bash
ssh admin@localhost -p 2222
# Password: password123 (use wrong password like 'wrong123')
```

### Test Web Honeypot:

```bash
curl http://localhost:8080
curl http://localhost:8080/wp-login.php
```

## 📊 Commands

| Command                      | Description                        |
| ---------------------------- | ---------------------------------- |
| `python main.py --all`       | Start all honeypots                |
| `python main.py --ssh`       | Start only SSH honeypot            |
| `python main.py --web`       | Start only WordPress honeypot      |
| `python main.py --dashboard` | Show real-time attack dashboard    |
| `python main.py --monitor`   | Start background attack monitoring |
| `python main.py --report`    | Generate attack report             |

## 📁 Project Structure

```
honeypot/
├── main.py              # Main controller
├── docker_manager.py    # Docker container management
├── attack_monitor.py    # Attack detection and logging
├── bait_creator.py      # Create fake credentials/files
├── containers/          # Docker configurations
│   ├── Dockerfile.ssh   # SSH honeypot image
│   └── ssh_logger.py    # SSH attack logger
├── logs/                # Attack logs (auto-created)
│   ├── all_attacks.json # All attacks in JSON format
│   ├── ssh_attacks.json # SSH-specific attacks
│   ├── web_attacks.json # Web-specific attacks
│   └── final_report.json# Generated reports
└── bait_files/          # Fake files to attract attackers
```

## 🐳 Docker Containers

| Container                 | Port | Description             |
| ------------------------- | ---- | ----------------------- |
| `real-ssh-honeypot`       | 2222 | SSH server with logging |
| `real-wordpress-honeypot` | 8080 | WordPress site          |
| `real-mysql-honeypot`     | 3306 | MySQL database          |

## 📈 What It Detects

### SSH Attacks:

- Failed password attempts
- Invalid user attempts
- Connection attempts

### Web Attacks:

- WordPress login attempts
- Suspicious paths (wp-admin, config files)
- Error responses

## ⚠️ Important Notes

1. **This is a REAL honeypot** - it will log actual attack attempts
2. **Use on isolated network** - exposing to internet will attract real attackers
3. **Test with wrong passwords** - use 'wrong123' not the real password
4. **Attacks may appear automatically** - background scans are normal

## 🛠️ Troubleshooting

**Issue:** No attacks detected  
**Solution:** Test manually: `ssh admin@localhost -p 2222` (use wrong password)

**Issue:** Docker not available  
**Solution:** Install Docker Desktop and run: `pip install docker`

**Issue:** Dashboard shows 0 attacks  
**Solution:** Attacks appear in real-time. Wait or trigger test attack.

## 📄 License

Educational project for security research

```

```
