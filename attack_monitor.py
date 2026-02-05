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

        # Track last check times
        self.last_ssh_check = datetime.now()

        # Create log directory
        os.makedirs(self.log_dir, exist_ok=True)

        # Initialize log files
        for log_file in [self.ssh_log_file]:  # FIXED: Make it a list
            if not os.path.exists(log_file):
                with open(log_file, 'w') as f:
                    f.write('')

    def log_ssh_attack(self, ip, username, status):
        """Log SSH attack attempt"""
        attack = {
            'timestamp': datetime.now().isoformat(),
            'service': 'ssh',
            'ip': ip,
            'username': username,
            'status': status,
            'type': 'ssh_authentication'
        }

        # Log to files
        with open(self.ssh_log_file, 'a') as f:
            f.write(json.dumps(attack) + '\n')

        print(f"[REAL SSH ATTACK] {ip} -> {username}")
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
                                    # Extract data
                                    ip = data.get('ip', 'unknown')
                                    username = data.get('username', 'unknown')
                                    status = data.get('status', 'attempted')

                                    # Log the attack
                                    if ip != 'unknown':
                                        self.log_ssh_attack(
                                            ip, username, status)

                            except json.JSONDecodeError:
                                # Not valid JSON, try to parse as SSH log
                                self.parse_ssh_log_line(line)
                            except:
                                continue
                        else:
                            # Parse regular SSH log line
                            self.parse_ssh_log_line(line)

        except Exception as e:
            print(f"[!] Container check error: {e}")

    def parse_ssh_log_line(self, line):
        """Parse SSH log line for attacks"""
        status = 'attempted'

        if 'Failed password' in line:
            status = 'failed_password'
        elif 'Invalid user' in line:
            status = 'invalid_user'
        elif 'Accepted password' in line:
            status = 'successful_login'  # Shouldn't happen in honeypot

        # Extract IP and username
        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
        ip = ip_match.group(1) if ip_match else None

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
            self.log_ssh_attack(ip, username, status)

    def is_duplicate(self, ip, username, service, seconds=2):
        """Check if attack was recently logged"""
        cutoff = datetime.now() - timedelta(seconds=seconds)

        try:
            with open(self.ssh_log_file, 'r') as f:
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
            with open(self.ssh_log_file, 'r') as f:
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
        ssh_count = len(attacks)  # All attacks are SSH now

        # Unique IPs
        ips = [a.get('ip') for a in attacks if a.get('ip')]
        unique_ips = len(set(ips))

        return {
            'total_attacks': ssh_count,  # Added this
            'ssh_attacks': ssh_count,
            'unique_attackers': unique_ips,
            'last_updated': datetime.now().isoformat()
        }

    def generate_report(self):
        """Generate comprehensive attack report"""
        attacks = []

        # Read all attacks
        try:
            with open(self.ssh_log_file, 'r') as f:
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
                'unique_attackers': 0,
                'top_attackers': [],
                'common_usernames': [],
                'attack_types': {},
                'recent_hour': 0,
                'generated_at': datetime.now().isoformat()
            }

        # Calculate stats
        ssh_count = len(attacks)

        # Unique IPs
        ips = [a.get('ip') for a in attacks if a.get('ip')]
        unique_ips = len(set(ips))

        # Top attackers
        ip_counter = Counter(ips)
        top_attackers = ip_counter.most_common(10)

        # Common usernames
        usernames = [a.get('username') for a in attacks if a.get('username')]
        common_usernames = Counter(usernames).most_common(10)

        # Attack types
        attack_types = {}
        for attack in attacks:
            status = attack.get('status', 'unknown')
            attack_types[status] = attack_types.get(status, 0) + 1

        # Recent activity
        recent = self.get_recent_attacks(minutes=60)

        return {
            'total_attacks': ssh_count,
            'ssh_attacks': ssh_count,
            'unique_attackers': unique_ips,
            'top_attackers': top_attackers,
            'common_usernames': common_usernames,
            'attack_types': attack_types,
            'recent_hour': len(recent),
            'generated_at': datetime.now().isoformat()
        }

    def get_attack_types(self, attacks):
        """Get distribution of attack types"""
        types = {}
        for attack in attacks:
            status = attack.get('status', 'unknown')
            types[status] = types.get(status, 0) + 1
        return dict(sorted(types.items(), key=lambda x: x[1], reverse=True))
