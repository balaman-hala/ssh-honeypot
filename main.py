
import argparse
import sys
import time
import threading
import os
from datetime import datetime

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import our modules
try:
    from docker_manager import DockerHoneypotManager
    from attack_monitor import AttackMonitor
    from bait_creator import BaitFileCreator
    print("[+] All modules loaded successfully")
except ImportError as e:
    print(f"[!] Import error: {e}")
    print("[*] Make sure these files are in the same directory:")
    print("    1. docker_manager.py")
    print("    2. attack_monitor.py")
    print("    3. bait_creator.py")
    sys.exit(1)


class RealHoneypotController:
    def __init__(self):
        self.docker_manager = DockerHoneypotManager()
        self.attack_monitor = AttackMonitor()
        self.bait_creator = BaitFileCreator()

        # Create necessary directories
        self.setup_directories()

    def setup_directories(self):
        """Create necessary directories"""
        directories = ['logs', 'bait_files', 'configs']
        for dir_name in directories:
            if not os.path.exists(dir_name):
                os.makedirs(dir_name)
                print(f"[+] Created {dir_name}/ directory")

    def check_docker(self):
        """Check if Docker is running"""
        return self.docker_manager.check_docker_installation()

    def start_real_ssh_honeypot(self):
        """Start REAL SSH server in Docker"""
        print("\n" + "="*60)
        print("STARTING REAL SSH HONEYPOT (Docker Container)")
        print("="*60)

        # Create bait files
        self.bait_creator.create_ssh_bait_files()

        # Start real SSH container
        container = self.docker_manager.start_ssh_container()

        if container:
            print(f"\n✅ REAL SSH Honeypot Started!")
            print(f"   Container: {container.name}")
            print(f"   Port: 2222")
            print(f"   Username: admin / root")
            print(f"   Password: password123 / toor")
            print(f"   Command: ssh admin@localhost -p 2222")
            print(f"   REAL Ubuntu 22.04 with OpenSSH server")
            print(f"\n⚠️  REAL attacks will be logged automatically!")
            return True
        else:
            print("[!] Failed to start SSH container")
            return False

    def start_real_wordpress_honeypot(self):
        """Start REAL WordPress in Docker"""
        print("\n" + "="*60)
        print("STARTING REAL WORDPRESS HONEYPOT (Docker Container)")
        print("="*60)

        # Create bait files
        self.bait_creator.create_wordpress_bait_files()

        # Start real WordPress container
        container = self.docker_manager.start_wordpress_container()

        if container:
            print(f"\n✅ REAL WordPress Honeypot Started!")
            print(f"   Container: {container.name}")
            print(f"   URL: http://localhost:8080")
            print(f"   Login: http://localhost:8080/wp-login.php")
            print(f"   Username: admin")
            print(f"   Password: admin123")
            print(f"   REAL WordPress with MySQL database")
            print(f"\n⚠️  REAL attacks will be logged automatically!")
            return True
        else:
            print("[!] Failed to start WordPress container")
            return False

    def start_all_real_honeypots(self):
        """Start both SSH and WordPress real honeypots"""
        print("\n" + "="*60)
        print("STARTING ALL REAL HONEYPOTS (Docker Containers)")
        print("="*60)

        # Create bait files
        self.bait_creator.create_ssh_bait_files()
        self.bait_creator.create_wordpress_bait_files()

        success = True

        # Start SSH
        if not self.docker_manager.start_ssh_container():
            print("[!] Failed to start SSH container")
            success = False

        # Start WordPress
        if not self.docker_manager.start_wordpress_container():
            print("[!] Failed to start WordPress container")
            success = False

        if success:
            print("\n" + "="*60)
            print("✅ ALL REAL HONEYPOTS STARTED!")
            print("="*60)
            print("\nAccess Points:")
            print("  SSH: ssh admin@localhost -p 2222")
            print("       Password: password123")
            print("  Web: http://localhost:8080")
            print("       Login: http://localhost:8080/wp-login.php")
            print("\n⚠️  REAL attacks will be logged automatically!")
            print("="*60)

        return success

    def start_monitoring(self):
        """Start monitoring attacks in background"""
        print("\n" + "="*60)
        print("STARTING REAL-TIME ATTACK MONITORING")
        print("="*60)

        # Start monitoring in background thread
        monitor_thread = threading.Thread(
            target=self.attack_monitor.start_monitoring,
            daemon=True
        )
        monitor_thread.start()

        print("[*] Attack monitor started in background")
        print("[*] Monitoring REAL Docker container logs")
        print("[*] Press Ctrl+C to stop")
        print("="*60)

        return monitor_thread

    def show_dashboard(self):
        """Show real-time dashboard"""
        os.system('cls' if os.name == 'nt' else 'clear')

        print("\n" + "="*60)
        print("🔥 REAL HONEYPOT DASHBOARD - REAL ATTACKS")
        print("="*60)
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-"*60)

        # Show running containers
        containers = self.docker_manager.list_containers()
        if containers:
            print("🚀 RUNNING CONTAINERS:")
            for container in containers:
                status = "✅" if container['status'] == 'running' else "⚠️ "
                print(
                    f"  {status} {container['name']} ({container['status']})")
                if container['ports']:
                    print(f"     Ports: {', '.join(container['ports'])}")
        else:
            print("❌ No honeypot containers running")
            print("[*] Start with: python main.py --all")

        # Show recent attacks
        recent_attacks = self.attack_monitor.get_recent_attacks(minutes=60)
        if recent_attacks:
            print(f"\n🔥 RECENT ATTACKS (last hour): {len(recent_attacks)}")
            print("-"*40)
            for attack in recent_attacks[-10:]:  # Last 10 attacks
                time_str = attack['timestamp'][11:19] if len(
                    attack['timestamp']) > 10 else attack['timestamp']
                service = "🛡️ SSH" if attack['service'] == 'ssh' else "🌐 WEB"
                ip = attack.get('ip', 'unknown')
                username = attack.get('username', '')
                if username:
                    print(f"  [{time_str}] {service}: {ip} -> {username}")
                else:
                    print(f"  [{time_str}] {service}: {ip}")
        else:
            print(f"\n👻 No attacks detected yet")
            print(f"  Try: ssh admin@localhost -p 2222")
            print(f"  Or: curl http://localhost:8080/wp-login.php")

        # Show statistics
        print("\n📊 STATISTICS:")
        stats = self.attack_monitor.get_stats()
        print(f"  Total Attacks: {stats['total_attacks']}")
        print(f"  SSH Attacks: {stats['ssh_attacks']}")
        print(f"  Web Attacks: {stats['web_attacks']}")
        print(f"  Unique Attackers: {stats['unique_attackers']}")
        print(f"  Last Updated: {stats['last_updated'][11:19]}")

        print("\n💡 TIPS:")
        print("  - Try wrong SSH passwords to test")
        print("  - Access web interface to test")
        print("  - Attacks appear in real-time")
        print("="*60)

    def run_dashboard_loop(self):
        """Run dashboard in loop"""
        try:
            while True:
                self.show_dashboard()
                time.sleep(5)  # Update every 5 seconds
        except KeyboardInterrupt:
            print("\n[*] Stopping dashboard...")

    def generate_report(self):
        """Generate attack report"""
        print("\n" + "="*60)
        print("📊 ATTACK REPORT")
        print("="*60)

        report = self.attack_monitor.generate_report()

        # Display report
        print(f"Total Attacks: {report['total_attacks']}")
        print(f"SSH Attacks: {report['ssh_attacks']}")
        print(f"Web Attacks: {report['web_attacks']}")
        print(f"Unique Attackers: {report['unique_attackers']}")
        print(f"Recent (1h): {report['recent_hour']}")

        if report['top_attackers']:
            print("\n🔝 TOP ATTACKERS:")
            for ip, count in report['top_attackers']:
                print(f"  {ip}: {count} attacks")

        if report['common_passwords']:
            print("\n🔑 COMMON PASSWORDS:")
            for pwd, count in report['common_passwords'][:5]:
                print(f"  '{pwd}': {count} attempts")

        # Save report
        report_file = 'logs/final_report.json'
        import json
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n📄 Report saved to: {report_file}")
        print("="*60)

    def run(self):
        """Main run method"""
        parser = argparse.ArgumentParser(
            description="Real Docker Honeypot System with REAL Attack Detection")
        parser.add_argument('--ssh', action='store_true',
                            help='Start REAL SSH honeypot')
        parser.add_argument('--web', action='store_true',
                            help='Start REAL WordPress honeypot')
        parser.add_argument('--all', action='store_true',
                            help='Start all REAL honeypots')
        parser.add_argument('--dashboard', action='store_true',
                            help='Show real-time dashboard')
        parser.add_argument('--monitor', action='store_true',
                            help='Start attack monitoring')
        parser.add_argument('--report', action='store_true',
                            help='Generate attack report')
        parser.add_argument('--cleanup', action='store_true',
                            help='Cleanup containers')

        args = parser.parse_args()

        print("="*60)
        print("🔥 REAL DOCKER HONEYPOT SYSTEM")
        print("DETECTS REAL ATTACKS - NO SIMULATION")
        print("="*60)

        # Check Docker first
        if not self.check_docker():
            print("[!] Docker is required for this honeypot!")
            print("[*] Please install Docker Desktop for Windows")
            print("[*] Then run: pip install docker")
            sys.exit(1)

        # Cleanup if requested
        if args.cleanup:
            self.docker_manager.cleanup_containers()
            return

        # Start services based on arguments
        if args.ssh:
            self.start_real_ssh_honeypot()
        elif args.web:
            self.start_real_wordpress_honeypot()
        elif args.all or not any([args.ssh, args.web, args.dashboard, args.monitor, args.report]):
            # Default: start everything
            self.start_all_real_honeypots()

        # Start monitoring
        if args.monitor or args.all or args.dashboard:
            self.start_monitoring()

        # Show dashboard
        if args.dashboard or args.all:
            try:
                self.run_dashboard_loop()
            except KeyboardInterrupt:
                print("\n[*] Stopping dashboard...")

        # Generate report
        if args.report:
            self.generate_report()

        # If nothing else, keep running
        if not (args.dashboard or args.report):
            print("\n" + "="*60)
            print("✅ HONEYPOTS RUNNING!")
            print("="*60)
            print("\nTest it yourself:")
            print("  SSH: ssh admin@localhost -p 2222")
            print("       (use wrong password to test)")
            print("  Web: http://localhost:8080")
            print("       http://localhost:8080/wp-login.php")
            print("\nCommands:")
            print("  Show live dashboard: python main.py --dashboard")
            print("  Generate report: python main.py --report")
            print("  Stop: Ctrl+C")
            print("="*60)

            try:
                # Keep running
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[*] Stopping honeypots...")

        # Generate final report and cleanup
        self.generate_report()
        self.docker_manager.cleanup_containers()


if __name__ == "__main__":
    try:
        controller = RealHoneypotController()
        controller.run()
    except KeyboardInterrupt:
        print("\n\n👋 Program stopped by user")
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
