
import os
import time
import json
from datetime import datetime


class DockerHoneypotManager:
    def __init__(self):
        self.client = None
        self.containers = {}
        self.docker_available = False

        # Try to import docker
        try:
            import docker
            self.docker = docker
            self.client = docker.from_env()
            self.docker_available = True
            print("[+] Docker client initialized")
        except ImportError:
            print("[!] docker module not installed")
            print("[*] Install with: pip install docker")
        except Exception as e:
            print(f"[!] Docker not available: {e}")

    def check_docker_installation(self):
        """Check if Docker is properly installed"""
        if not self.docker_available:
            return False

        try:
            self.client.ping()
            print("[+] Docker is running")
            return True
        except Exception as e:
            print(f"[!] Docker error: {e}")
            return False

    def build_ssh_image(self):
        """Build custom SSH honeypot image with logging"""
        print("[*] Building SSH honeypot Docker image with REAL logging...")

        # Create containers directory if it doesn't exist
        os.makedirs('containers', exist_ok=True)

        # Create ssh_logger.py
        ssh_logger = '''#!/usr/bin/env python3
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
    
    # Also write to file
    with open("/var/log/ssh_attacks.log", "a") as f:
        f.write(json.dumps(attack) + "\\n")

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
            ip_match = re.search(r'from (\\d+\\.\\d+\\.\\d+\\.\\d+)', line)
            ip = ip_match.group(1) if ip_match else "unknown"
            
            # Extract username
            user_match = re.search(r'for (\\w+) from', line)
            username = user_match.group(1) if user_match else "unknown"
            
            if ip != "unknown":
                log_attack(ip, username, "failed")
                print(f"[ATTACK] Failed login: {ip} -> {username}", flush=True)
                
        elif "Invalid user" in line:
            ip_match = re.search(r'from (\\d+\\.\\d+\\.\\d+\\.\\d+)', line)
            ip = ip_match.group(1) if ip_match else "unknown"
            
            user_match = re.search(r'Invalid user (\\w+)', line)
            username = user_match.group(1) if user_match else "unknown"
            
            if ip != "unknown":
                log_attack(ip, username, "invalid_user")
                print(f"[ATTACK] Invalid user: {ip} -> {username}", flush=True)
                
        elif "Accepted password" in line:
            ip_match = re.search(r'from (\\d+\\.\\d+\\.\\d+\\.\\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                print(f"[SUCCESS] Login successful: {ip}", flush=True)

ssh.wait()
'''

        with open('containers/ssh_logger.py', 'w') as f:
            f.write(ssh_logger)

        dockerfile = '''FROM ubuntu:22.04

# Install SSH and Python
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    openssh-server \
    sudo \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Create user
RUN useradd -m -s /bin/bash admin && \
    echo "admin:password123" | chpasswd && \
    usermod -aG sudo admin

# Create root password
RUN echo "root:toor" | chpasswd

# Configure SSH for maximum logging
RUN mkdir /var/run/sshd
RUN echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
RUN echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
RUN echo "AllowUsers admin root" >> /etc/ssh/sshd_config
RUN echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config
RUN echo "MaxAuthTries 100" >> /etc/ssh/sshd_config

# Copy logger script
COPY containers/ssh_logger.py /ssh_logger.py
RUN chmod +x /ssh_logger.py

# Generate SSH host keys
RUN ssh-keygen -A

EXPOSE 22

# Start with our logger
CMD ["python3", "/ssh_logger.py"]
'''

        with open('containers/Dockerfile.ssh', 'w') as f:
            f.write(dockerfile)

        # Build image
        try:
            image, build_logs = self.client.images.build(
                path='.',
                dockerfile='containers/Dockerfile.ssh',
                tag='honeypot-ssh',
                rm=True
            )
            print("[+] SSH honeypot image built successfully")
            return image
        except Exception as e:
            print(f"[!] Failed to build image: {e}")
            return None

    def start_ssh_container(self):
        """Start REAL SSH honeypot container"""
        if not self.docker_available:
            print("[!] Docker not available")
            return None

        try:
            # Clean up old container
            try:
                old = self.client.containers.get('real-ssh-honeypot')
                old.stop()
                old.remove()
                print("[*] Removed old SSH container")
            except:
                pass

            # Build or pull image
            try:
                self.client.images.get('honeypot-ssh')
                print("[+] Using existing SSH honeypot image")
            except:
                print("[*] Building new SSH honeypot image...")
                self.build_ssh_image()

            # Start container
            print("[*] Starting REAL SSH honeypot container...")
            container = self.client.containers.run(
                'honeypot-ssh',
                detach=True,
                ports={'22/tcp': 2222},
                name='real-ssh-honeypot',
                restart_policy={'Name': 'unless-stopped'},
                volumes={
                    os.path.abspath('bait_files'): {'bind': '/home/admin/bait', 'mode': 'ro'}
                }
            )

            self.containers['ssh'] = container
            print(f"[+] REAL SSH container started: {container.id[:12]}")
            print(f"[+] SSH port: 2222")
            print(f"[+] Test: ssh admin@localhost -p 2222")
            print(f"[+] Password: password123 (use wrong password to test)")

            # Wait for SSH to start
            time.sleep(3)
            return container

        except Exception as e:
            print(f"[!] Failed to start SSH container: {e}")
            return None

    def start_wordpress_container(self):
        """Start REAL WordPress honeypot container"""
        if not self.docker_available:
            print("[!] Docker not available")
            return None

        try:
            # Clean up old containers
            for name in ['real-wordpress-honeypot', 'real-mysql-honeypot']:
                try:
                    old = self.client.containers.get(name)
                    old.stop()
                    old.remove()
                    print(f"[*] Removed old {name}")
                except:
                    pass

            # Start MySQL
            print("[*] Starting MySQL container...")
            mysql = self.client.containers.run(
                'mysql:8.0',
                detach=True,
                name='real-mysql-honeypot',
                environment={
                    'MYSQL_ROOT_PASSWORD': 'rootpassword',
                    'MYSQL_DATABASE': 'wordpress',
                    'MYSQL_USER': 'wordpress',
                    'MYSQL_PASSWORD': 'wordpress123'
                },
                restart_policy={'Name': 'unless-stopped'}
            )
            self.containers['mysql'] = mysql
            print(f"[+] MySQL started: {mysql.id[:12]}")

            # Wait for MySQL
            time.sleep(10)

            # Start WordPress with access logging
            print("[*] Starting WordPress container...")

            # Create custom entrypoint for WordPress to log access
            wp_entrypoint = '''#!/bin/bash
# Start Apache with custom log format
echo "LogFormat \\"{\\"timestamp\\":\\"%t\\",\\"ip\\":\\"%a\\",\\"method\\":\\"%r\\",\\"status\\":\\"%>s\\",\\"user_agent\\":\\"%{User-agent}i\\"}\\" json" > /etc/apache2/apache2.conf
echo 'CustomLog /proc/self/fd/1 json' >> /etc/apache2/apache2.conf

# Start Apache in foreground
exec apache2-foreground
'''

            # Start container
            wp = self.client.containers.run(
                'wordpress:latest',
                detach=True,
                name='real-wordpress-honeypot',
                ports={'80/tcp': 8080},
                environment={
                    'WORDPRESS_DB_HOST': 'real-mysql-honeypot',
                    'WORDPRESS_DB_USER': 'wordpress',
                    'WORDPRESS_DB_PASSWORD': 'wordpress123',
                    'WORDPRESS_DB_NAME': 'wordpress',
                    'WORDPRESS_CONFIG_EXTRA': "define('WP_DEBUG', true);"
                },
                restart_policy={'Name': 'unless-stopped'},
                volumes={
                    os.path.abspath('bait_files/wordpress'): {
                        'bind': '/var/www/html/wp-content/uploads/bait',
                        'mode': 'ro'
                    }
                }
            )

            self.containers['wordpress'] = wp
            print(f"[+] WordPress started: {wp.id[:12]}")
            print(f"[+] Web port: 8080")
            print(f"[+] URL: http://localhost:8080")
            print(f"[+] Login: http://localhost:8080/wp-login.php")

            return wp

        except Exception as e:
            print(f"[!] Failed to start WordPress: {e}")
            return None

    def get_container_by_name(self, name):
        """Get container by name"""
        if not self.docker_available:
            return None

        try:
            return self.client.containers.get(name)
        except:
            return None

    def list_containers(self):
        """List all running honeypot containers"""
        if not self.docker_available:
            return []

        try:
            containers = self.client.containers.list(all=True)
            honeypot_containers = []

            for container in containers:
                if 'honeypot' in container.name:
                    ports = []
                    if container.ports:
                        for port_info in container.ports.values():
                            if port_info:
                                ports.append(port_info[0]['HostPort'])

                    honeypot_containers.append({
                        'name': container.name,
                        'id': container.id[:12],
                        'status': container.status,
                        'ports': ports,
                        'image': container.image.tags[0] if container.image.tags else 'unknown'
                    })

            return honeypot_containers

        except Exception as e:
            print(f"[!] Error listing containers: {e}")
            return []

    def cleanup_containers(self):
        """Stop and remove all honeypot containers"""
        if not self.docker_available:
            return

        print("\n[*] Cleaning up containers...")

        containers_to_remove = [
            'real-ssh-honeypot',
            'real-wordpress-honeypot',
            'real-mysql-honeypot'
        ]

        for name in containers_to_remove:
            try:
                container = self.client.containers.get(name)
                print(f"[*] Stopping {name}...")
                container.stop()
                container.remove()
                print(f"[+] Stopped {name}")
            except:
                pass

        self.containers = {}
        print("[+] All containers cleaned up")
