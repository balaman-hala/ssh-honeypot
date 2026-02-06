
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

        os.makedirs('containers', exist_ok=True)

        # Copy YOUR working Dockerfile
        with open('Dockerfile', 'r') as f:
            dockerfile_content = f.read()

        with open('containers/Dockerfile', 'w') as f:
            f.write(dockerfile_content)

        print("[+] Copied working Dockerfile")

        # Build image
        try:
            image, build_logs = self.client.images.build(
                path='.',
                dockerfile='containers/Dockerfile',
                tag='honeypot-ssh',
                rm=True
            )
            print("[+] SSH honeypot image built successfully")
            return image
        except Exception as e:
            print(f"[!] Failed to build image: {e}")
            return None

    def start_ssh_container(self):
        os.makedirs('logs', exist_ok=True)
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
                    os.path.abspath('bait_files'): {'bind': '/home/admin/bait', 'mode': 'ro'},
                    os.path.abspath('logs'): {'bind': '/var/log/ssh_sessions', 'mode': 'rw'}
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
            'real-ssh-honeypot'
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
