import subprocess
import re
import json
import os
from datetime import datetime
import threading


def log_attack(ip, username, status):
    """Log attack in JSON format"""
    attack = {
        "timestamp": datetime.now().isoformat(),
        "service": "ssh",
        "ip": ip,
        "username": username,
        "status": status,
        "type": "ssh_auth"
    }
    # Print JSON to stdout (captured by Docker)
    print(json.dumps(attack), flush=True)


print("[SSH Logger] Starting SSH server with attack logging...", flush=True)

# Start SSH with debug mode
ssh = subprocess.Popen(
    ["/usr/sbin/sshd", "-D", "-e", "-ddd"],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
    bufsize=1,
    universal_newlines=True
)

# Monitor SSH output
for line in iter(ssh.stdout.readline, ''):
    line = line.strip()
    if line:
        # Print original for debugging
        print(f"[SSH] {line}", flush=True)

        # Check for failed logins
        if "Failed password" in line:
            # Extract IP
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            ip = ip_match.group(1) if ip_match else "unknown"

            # Extract username
            user_match = re.search(r'for (\w+) from', line)
            username = user_match.group(1) if user_match else "unknown"

            if ip != "unknown":
                log_attack(ip, username, "failed")
                print(f"[ATTACK] Failed login: {ip} -> {username}", flush=True)

        elif "Invalid user" in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            ip = ip_match.group(1) if ip_match else "unknown"

            user_match = re.search(r'Invalid user (\w+)', line)
            username = user_match.group(1) if user_match else "unknown"

            if ip != "unknown":
                log_attack(ip, username, "invalid_user")
                print(f"[ATTACK] Invalid user: {ip} -> {username}", flush=True)

        elif "Accepted password" in line:
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                print(f"[SUCCESS] Login successful: {ip}", flush=True)


def watch_command_logs():
    """Watch for new command log files"""
    log_dir = "/var/log/ssh_sessions/"

    while True:
        try:
            # Check for new log files
            for file in os.listdir(log_dir):
                if file.endswith('.log'):
                    filepath = os.path.join(log_dir, file)
                    # Read and broadcast new content
                    with open(filepath, 'r') as f:
                        content = f.read()
                        if content:
                            event = {
                                "timestamp": datetime.now().isoformat(),
                                "type": "shell_command",
                                "content": content[-500:],  # Last 500 chars
                                "logfile": file
                            }
                            print(json.dumps(event), flush=True)
        except:
            pass

        time.sleep(5)


# Start watching in background
threading.Thread(target=watch_command_logs, daemon=True).start()
ssh.wait()

