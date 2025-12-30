#!/usr/bin/env python3
"""
SSH LOGGER - Logs all SSH attempts in JSON format
"""
import subprocess
import re
import json
import sys
from datetime import datetime


def log_attack(ip, username, status):
    """Log attack in JSON format"""
    attack = {
        "timestamp": datetime.now().isoformat(),
        "service": "ssh",
        "ip": ip,
        "username": username,
        "password": "[attempted]",
        "status": status,
        "type": "ssh_auth"
    }
    # Print JSON to stdout (captured by Docker)
    print(json.dumps(attack), flush=True)

    # Also write to file inside container
    with open("/var/log/ssh_attacks.log", "a") as f:
        f.write(json.dumps(attack) + "\n")


print("[SSH Logger] Starting SSH server with attack logging...", flush=True)
print("[SSH Logger] All login attempts will be logged!", flush=True)

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

ssh.wait()
