#!/usr/bin/env python3
"""
MONITORS REAL ATTACKS ON DOCKER CONTAINERS - NO SIMULATION
"""
import os
import json
import time
import re
from datetime import datetime, timedelta
from collections import Counter
import subprocess


class AttackMonitor:
    def __init__(self):
        self.log_dir = 'logs'
        self.ssh_log_file = os.path.join(self.log_dir, 'ssh_attacks.json')
        self.web_log_file = os.path.join(self.log_dir, 'web_attacks.json')
        self.all_log_file = os.path.join(self.log_dir, 'all_attacks.json')

        # Track last check times
        self.last_ssh_check = datetime.now()
        self.last_web_check = datetime.now()

        # Create log directory
        os.makedirs(self.log_dir, exist_ok=True)

        # Initialize log files
        for log_file in [self.ssh_log_file, self.web_log_file, self.all_log_file]:
            if not os.path.exists(log_file):
                with open(log_file, 'w') as f:
                    f.write('')

    def log_ssh_attack(self, ip, username, password):
        """Log SSH attack attempt"""
        attack = {
            'timestamp': datetime.now().isoformat(),
            'service': 'ssh',
            'ip': ip,
            'username': username,
            'password': password,
            'type': 'ssh_authentication'
        }

        # Log to files
        with open(self.ssh_log_file, 'a') as f:
            f.write(json.dumps(attack) + '\n')
        with open(self.all_log_file, 'a') as f:
            f.write(json.dumps(attack) + '\n')

        print(f"[REAL SSH ATTACK] {ip} -> {username}:{password}")
        return attack

    def log_web_attack(self, ip, path, username='', password='', user_agent=''):
        """Log web attack attempt"""
        attack = {
            'timestamp': datetime.now().isoformat(),
            'service': 'web',
            'ip': ip,
            'path': path,
            'username': username,
            'password': password,
            'user_agent': user_agent,
            'type': 'http_request'
        }

        # Log to files
        with open(self.web_log_file, 'a') as f:
            f.write(json.dumps(attack) + '\n')
        with open(self.all_log_file, 'a') as f:
            f.write(json.dumps(attack) + '\n')

        if username or password:
            print(f"[REAL WEB ATTACK] {ip} -> {path} ({username}:{password})")
        else:
            print(f"[REAL WEB ATTACK] {ip} -> {path}")

        return attack

    def monitor_docker_logs(self):
        """Monitor REAL Docker container logs for attacks"""
        print("[*] Starting REAL attack monitoring...")
        print("[*] Monitoring Docker container logs...")
        print("[*] Attacks will appear as they happen!")

        while True:
            try:
                # Check SSH container
                self.check_ssh_container()

                # Check WordPress container
                self.check_web_container()

                # Sleep
                time.sleep(2)

            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[!] Monitoring error: {e}")
                time.sleep(5)

    def check_ssh_container(self):
        """Check SSH container for attacks"""
        try:
            # Use docker command directly to get logs
            cmd = ['docker', 'logs', '--since', '5s', 'real-ssh-honeypot']
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.stdout:
                lines = result.stdout.split('\n')
                for line in lines:
                    line = line.strip()
                    if line:
                        # Try to parse as JSON attack log
                        if line.startswith('{') and line.endswith('}'):
                            try:
                                data = json.loads(line)
                                if data.get('service') == 'ssh':
                                    # Log the attack
                                    self.log_ssh_attack(
                                        ip=data.get('ip', 'unknown'),
                                        username=data.get(
                                            'username', 'unknown'),
                                        password=data.get(
                                            'password', '[attempted]')
                                    )
                            except:
                                # Not JSON, try to parse as SSH log
                                self.parse_ssh_log_line(line)
                        else:
                            # Parse regular SSH log
                            self.parse_ssh_log_line(line)

        except Exception as e:
            pass  # Silent fail, container might not be ready

    def parse_ssh_log_line(self, line):
        """Parse SSH log line for attacks"""
        # Look for failed login patterns
        if 'Failed password' in line or 'Invalid user' in line:
            # Extract IP
            ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
            ip = ip_match.group(1) if ip_match else None

            # Extract username
            username = 'unknown'
            if 'for invalid user' in line:
                match = re.search(r'for invalid user (\w+)', line)
                if match:
                    username = match.group(1)
            elif 'for' in line:
                match = re.search(r'for (\w+) from', line)
                if match:
                    username = match.group(1)

            if ip and not self.is_duplicate(ip, username, 'ssh', seconds=10):
                self.log_ssh_attack(ip, username, '[attempted]')

    def check_web_container(self):
        """Check WordPress container for attacks"""
        try:
            # Get web container logs
            cmd = ['docker', 'logs', '--since',
                   '5s', 'real-wordpress-honeypot']
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.stdout:
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if line:
                        # Look for login attempts
                        if '/wp-login.php' in line or 'POST' in line:
                            # Try to extract IP
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            ip = ip_match.group(1) if ip_match else None

                            if ip:
                                # Check if it's a failed login (403, 401, or contains error)
                                if any(x in line for x in [' 403 ', ' 401 ', 'Invalid', 'failed', 'error']):
                                    if not self.is_duplicate(ip, '', 'web', seconds=10):
                                        self.log_web_attack(
                                            ip=ip,
                                            path='/wp-login.php',
                                            username='[attempted]',
                                            password='[attempted]',
                                            user_agent=''
                                        )

                        # Look for suspicious paths
                        suspicious = ['wp-admin', 'admin', 'phpmyadmin',
                                      'config', '.env', 'backup', 'shell']
                        if any(path in line.lower() for path in suspicious):
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if ip_match:
                                ip = ip_match.group(1)
                                if not self.is_duplicate(ip, '', 'web', seconds=10):
                                    self.log_web_attack(
                                        ip=ip, path='[scan]', user_agent='scanner')

        except Exception as e:
            pass  # Silent fail

    def is_duplicate(self, ip, username, service, seconds=2):
        """Check if attack was recently logged"""
        cutoff = datetime.now() - timedelta(seconds=seconds)

        try:
            with open(self.all_log_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            attack = json.loads(line)
                            attack_time = datetime.fromisoformat(
                                attack['timestamp'].replace('Z', '+00:00'))

                            if (attack['ip'] == ip and
                                attack.get('username') == username and
                                attack['service'] == service and
                                    attack_time > cutoff):
                                return True
                        except:
                            pass
        except:
            pass
        return False

    def start_monitoring(self):
        """Start attack monitoring"""
        self.monitor_docker_logs()

    def get_recent_attacks(self, minutes=60):
        """Get attacks from last N minutes"""
        attacks = []
        cutoff = datetime.now() - timedelta(minutes=minutes)

        try:
            with open(self.all_log_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            attack = json.loads(line)
                            timestamp = attack.get('timestamp', '')
                            if timestamp:
                                # Parse timestamp
                                if 'Z' in timestamp:
                                    timestamp = timestamp.replace(
                                        'Z', '+00:00')
                                attack_time = datetime.fromisoformat(timestamp)

                                if attack_time > cutoff:
                                    attacks.append(attack)
                        except:
                            continue
        except:
            pass

        return attacks

    def get_stats(self):
        """Get attack statistics"""
        attacks = self.get_recent_attacks(minutes=1440)  # 24 hours

        # Calculate stats
        ssh_count = sum(1 for a in attacks if a.get('service') == 'ssh')
        web_count = sum(1 for a in attacks if a.get('service') == 'web')

        # Unique IPs
        ips = [a.get('ip') for a in attacks if a.get('ip')]
        unique_ips = len(set(ips))

        return {
            'total_attacks': len(attacks),
            'ssh_attacks': ssh_count,
            'web_attacks': web_count,
            'unique_attackers': unique_ips,
            'last_updated': datetime.now().isoformat()
        }

    def generate_report(self):
        """Generate comprehensive attack report"""
        attacks = []

        # Read all attacks
        try:
            with open(self.all_log_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            attack = json.loads(line)
                            attacks.append(attack)
                        except:
                            continue
        except:
            pass

        if not attacks:
            return {
                'total_attacks': 0,
                'ssh_attacks': 0,
                'web_attacks': 0,
                'unique_attackers': 0,
                'top_attackers': [],
                'common_passwords': [],
                'common_usernames': [],
                'recent_hour': 0,
                'generated_at': datetime.now().isoformat()
            }

        # Calculate stats
        ssh_count = sum(1 for a in attacks if a.get('service') == 'ssh')
        web_count = sum(1 for a in attacks if a.get('service') == 'web')

        # Unique IPs
        ips = [a.get('ip') for a in attacks if a.get('ip')]
        unique_ips = len(set(ips))

        # Top attackers
        ip_counter = Counter(ips)
        top_attackers = ip_counter.most_common(10)

        # Common passwords
        passwords = [a.get('password') for a in attacks if a.get('password')]
        common_passwords = Counter(passwords).most_common(10)

        # Common usernames
        usernames = [a.get('username') for a in attacks if a.get('username')]
        common_usernames = Counter(usernames).most_common(10)

        # Recent activity
        recent = self.get_recent_attacks(minutes=60)

        return {
            'total_attacks': len(attacks),
            'ssh_attacks': ssh_count,
            'web_attacks': web_count,
            'unique_attackers': unique_ips,
            'top_attackers': top_attackers,
            'common_passwords': common_passwords,
            'common_usernames': common_usernames,
            'recent_hour': len(recent),
            'generated_at': datetime.now().isoformat()
        }
