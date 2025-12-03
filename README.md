# Honeypot Project

A multi-service honeypot that simulates SSH and WordPress admin login pages to capture and log intrusion attempts.

## Features

- **SSH Honeypot**: Fake SSH server with interactive shell emulation
- **HTTP Honeypot**: Fake WordPress admin login page
- **Comprehensive Logging**: All connection attempts and credentials logged
- **Customizable Credentials**: Set custom usernames and passwords
- **Realistic Responses**: Emulates real system behavior

## Quick Start

### Prerequisites
- Python 3.6+
- Required packages: `paramiko`, `flask`

### Installation

1. **Clone or download the project files**
2. **Install dependencies** (if not already installed):
   ```bash
   pip3 install --user paramiko flask
   ```

3. **One-time setup**:
   ```bash
   # Generate SSH server key
   ssh-keygen -t rsa -f server.key -N "" -q
   
   # Create templates directory
   mkdir -p templates
   
   # Move HTML file to templates (if needed)
   mv wp-admin.html templates/
   ```

## Usage

### Running SSH Honeypot

**Basic usage (localhost):**
```bash
python3 honeypot.py -a 127.0.0.1 -p 2222 --ssh
```

**Network accessible:**
```bash
python3 honeypot.py -a 0.0.0.0 -p 2222 --ssh
```

**With custom credentials:**
```bash
python3 honeypot.py -a 0.0.0.0 -p 2222 -u admin -pw password123 --ssh
```

### Running HTTP Honeypot

**Basic usage (localhost):**
```bash
python3 honeypot.py -a 127.0.0.1 -p 8080 --http
```

**Network accessible:**
```bash
python3 honeypot.py -a 0.0.0.0 -p 8080 --http
```

**With custom credentials:**
```bash
python3 honeypot.py -a 0.0.0.0 -p 8080 -u wpadmin -pw P@ssw0rd --http
```

### Testing Your Honeypots

**Test SSH Honeypot:**
```bash
ssh test@127.0.0.1 -p 2222
```
- Use any username/password combination
- Try commands: `help`, `ls`, `whoami`, `pwd`, `exit`

**Test HTTP Honeypot:**
1. Open web browser
2. Navigate to: `http://127.0.0.1:8080`
3. Try logging in with default credentials: `admin` / `password`

## Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `-a, --address` | IP address to bind to | `-a 0.0.0.0` |
| `-p, --port` | Port to listen on | `-p 2222` |
| `-u, --username` | Custom username | `-u admin` |
| `-pw, --password` | Custom password | `-pw secret` |
| `-s, --ssh` | Run SSH honeypot | `--ssh` |
| `-w, --http` | Run HTTP honeypot | `--http` |

## Log Files

The honeypot creates three log files:

- **`system.log`**: SSH connection attempts and authentication logs
- **`cmd_system.log`**: SSH command execution logs  
- **`http_system.log`**: HTTP login attempts with credentials

**View logs in real-time:**
```bash
tail -f system.log      # SSH connections
tail -f cmd_system.log  # SSH commands
tail -f http_system.log # HTTP logins
```

## File Structure
```
honeypot-project/
├── honeypot.py          # Main launcher script
├── ssh_honeypot.py      # SSH honeypot implementation
├── web_honeypot.py      # HTTP honeypot implementation
├── server.key           # SSH host key (generated)
├── templates/
│   └── wp-admin.html    # WordPress login page template
├── system.log           # SSH logs (auto-generated)
├── cmd_system.log       # Command logs (auto-generated)
└── http_system.log      # HTTP logs (auto-generated)
```

## Examples

**Capture SSH attacks on standard port:**
```bash
sudo python3 honeypot.py -a 0.0.0.0 -p 22 --ssh
```

**Capture WordPress login attempts:**
```bash
python3 honeypot.py -a 0.0.0.0 -p 80 -u administrator -pw "P@ssw0rd123" --http
```

**Run both services simultaneously:**
- Terminal 1: `python3 honeypot.py -a 0.0.0.0 -p 2222 --ssh`
- Terminal 2: `python3 honeypot.py -a 0.0.0.0 -p 8080 --http`

## Security Notes

⚠️ **Important Security Warnings:**

- Only run on isolated networks or dedicated monitoring systems
- Do not run on production systems with sensitive data
- The honeypot accepts all SSH connections - ensure proper firewall rules
- Log files may contain sensitive attacker data - handle appropriately
- Using privileged ports (below 1024) requires root access

## Troubleshooting

**"404 Not Found" for HTTP honeypot:**
- Ensure `wp-admin.html` is in the `templates/` directory
- Run from the directory containing `honeypot.py`

**"Module not found" errors:**
- Install required packages: `pip3 install --user paramiko flask`

**"Permission denied" on port 22/80:**
- Use `sudo` for privileged ports, or use higher ports (2222, 8080, etc.)

**SSH key generation issues:**
- Manually generate: `ssh-keygen -t rsa -f server.key -N ""`

## Stopping the Honeypot

Press `Ctrl + C` in the terminal where the honeypot is running.

## Legal and Ethical Use

- Only deploy on networks you own or have explicit permission to monitor
- Compliance with local laws and regulations is required
- Use responsibly for security research and education only

---

