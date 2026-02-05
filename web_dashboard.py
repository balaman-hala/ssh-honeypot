# web_dashboard.py - FIXED VERSION
import os
import json
import threading
import time
import datetime as dt  # Rename to avoid conflict
from collections import Counter, defaultdict
from flask import Flask, render_template, request, jsonify, Response
from flask_socketio import SocketIO, emit
from geopy.geocoders import Nominatim

import requests
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.security import generate_password_hash, check_password_hash

try:
    from attack_monitor import AttackMonitor
    from docker_manager import DockerHoneypotManager
    from bait_creator import BaitFileCreator
    print("[+] Imported existing modules")
except ImportError:
    print("[!] Could not import existing modules")
    AttackMonitor = None
    DockerHoneypotManager = None
    BaitFileCreator = None

from config import Config


class HoneypotDashboard:
    def __init__(self):
        self.app = Flask(__name__,
                         template_folder='templates',
                         static_folder='static')
        self.app.config.from_object(Config)
        self.socketio = SocketIO(
            self.app, cors_allowed_origins="*", async_mode='threading')

        # Initialize components
        self.attack_monitor = AttackMonitor() if AttackMonitor else None
        self.docker_manager = DockerHoneypotManager() if DockerHoneypotManager else None

        # Data storage
        self.recent_attacks = []
        self.attack_stats = {}
        self.geo_data = {}
        self.alerts = []

        # Threading
        self.running = True
        self.update_thread = None
        self.scheduler = BackgroundScheduler()

        # Geolocation
        self.geolocator = Nominatim(user_agent="honeypot_dashboard")
        self.geoip_reader = None
        self.init_geolocation()

        # Threat intelligence cache
        self.ip_reputation_cache = {}

        # Setup routes
        self.setup_routes()
        self.setup_socketio_events()

        # Start background tasks
        self.start_background_tasks()

        # Add context processor for 'now' function
        @self.app.context_processor
        def inject_now():
            return {'now': dt.datetime.now}

    def init_geolocation(self):
        """Initialize geolocation services"""
        print("[*] Using free IP geolocation API (ip-api.com)")
        print("[!] Note: Limited to 45 requests per minute")
        self.geoip_reader = None

    def get_ip_location(self, ip_address):
        """Get location information for an IP address"""
        if ip_address in self.geo_data:
            return self.geo_data[ip_address]

        location_info = {
            'ip': ip_address,
            'country': 'Unknown',
            'city': 'Unknown',
            'latitude': 0,
            'longitude': 0,
            'asn': 'Unknown',
            'isp': 'Unknown'
        }

        try:
            # Try free ip-api.com (rate limited)
            response = requests.get(
                f"http://ip-api.com/json/{ip_address}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    location_info['country'] = data.get('country', 'Unknown')
                    location_info['city'] = data.get('city', 'Unknown')
                    location_info['latitude'] = data.get('lat', 0)
                    location_info['longitude'] = data.get('lon', 0)
                    location_info['isp'] = data.get('isp', 'Unknown')
                    location_info['asn'] = data.get('as', 'Unknown')
        except Exception as e:
            print(f"[!] Error getting location from API: {e}")

        # Cache the result
        self.geo_data[ip_address] = location_info
        return location_info

    def get_ip_reputation(self, ip_address):
        """Check IP reputation using threat intelligence"""
        if ip_address in self.ip_reputation_cache:
            return self.ip_reputation_cache[ip_address]

        reputation = {
            'ip': ip_address,
            'abuse_score': 0,
            'is_malicious': False,
            'threat_types': [],
            'last_reported': None,
            'sources_checked': []
        }

        # Check AbuseIPDB (if API key available)
        api_key = getattr(Config, 'ABUSEIPDB_API_KEY', None)
        if api_key:
            try:
                url = "https://api.abuseipdb.com/api/v2/check"
                headers = {
                    'Key': api_key,
                    'Accept': 'application/json'
                }
                params = {
                    'ipAddress': ip_address,
                    'maxAgeInDays': 90
                }

                response = requests.get(
                    url, headers=headers, params=params, timeout=5)
                if response.status_code == 200:
                    data = response.json().get('data', {})
                    reputation['abuse_score'] = data.get(
                        'abuseConfidenceScore', 0)
                    reputation['is_malicious'] = data.get(
                        'abuseConfidenceScore', 0) > 50
                    reputation['last_reported'] = data.get('lastReportedAt')
                    reputation['sources_checked'].append('AbuseIPDB')
            except Exception as e:
                print(f"[!] Error checking AbuseIPDB: {e}")

        # Cache the result for 1 hour
        self.ip_reputation_cache[ip_address] = reputation
        return reputation

    def send_alert(self, alert_type, severity, message, data=None):
        """Send alert notifications"""
        alert = {
            'id': f"alert_{int(time.time())}_{len(self.alerts)}",
            'type': alert_type,
            'severity': severity,  # 'info', 'warning', 'danger', 'critical'
            'message': message,
            'data': data or {},
            'timestamp': dt.datetime.now().isoformat(),
            'acknowledged': False
        }

        self.alerts.append(alert)

        # Keep only last 100 alerts
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]

        # Send via SocketIO
        self.socketio.emit('new_alert', alert)

        print(f"[ALERT] {severity.upper()}: {message}")
        return alert

    def update_stats(self):
        """Update dashboard statistics"""
        if not self.attack_monitor:
            return

        try:
            # Get recent attacks (SSH only)
            recent = self.attack_monitor.get_recent_attacks(minutes=60)
            self.recent_attacks = recent[-50:]  # Keep last 50

            # Calculate statistics
            stats = self.attack_monitor.get_stats()

            # Enhanced stats
            now = dt.datetime.now()

            # Attacks by hour
            attacks_by_hour = defaultdict(int)
            for attack in recent:
                try:
                    timestamp_str = attack['timestamp']
                    if 'Z' in timestamp_str:
                        timestamp_str = timestamp_str.replace('Z', '+00:00')
                    timestamp = dt.datetime.fromisoformat(timestamp_str)
                    hour = timestamp.strftime('%H:00')
                    attacks_by_hour[hour] += 1
                except (KeyError, ValueError):
                    continue

            # Top attacking countries
            countries = Counter()
            for attack in recent:
                ip = attack.get('ip')
                if ip:
                    location = self.get_ip_location(ip)
                    countries[location['country']] += 1

            # Common usernames
            usernames = Counter()
            for attack in recent:
                if attack.get('username'):
                    usernames[attack['username']] += 1

            self.attack_stats = {
                'basic': stats,
                'by_hour': dict(attacks_by_hour),
                'by_country': dict(countries.most_common(10)),
                'top_usernames': dict(usernames.most_common(10)),
                'update_time': now.isoformat()
            }

            # Check for alert conditions
            self.check_alerts(recent)

            # Emit update via SocketIO
            self.socketio.emit('stats_update', self.attack_stats)
            self.socketio.emit('recent_attacks', self.recent_attacks[-10:])

        except Exception as e:
            print(f"[!] Error updating stats: {e}")

    def check_alerts(self, recent_attacks):
        """Check for alert conditions"""
        if not recent_attacks:
            return

        # Group attacks by IP
        ip_activity = defaultdict(int)
        for attack in recent_attacks:
            ip = attack.get('ip', 'unknown')
            ip_activity[ip] += 1

        # Check thresholds
        alert_threshold_ssh = getattr(Config, 'ALERT_THRESHOLD_SSH', 5)

        for ip, count in ip_activity.items():
            if count >= alert_threshold_ssh:
                self.send_alert(
                    alert_type='ssh_bruteforce',
                    severity='danger' if count > 10 else 'warning',
                    message=f"SSH bruteforce detected from {ip} ({count} attempts)",
                    data={'ip': ip, 'count': count, 'service': 'ssh'}
                )

        # Check for new attacking countries
        new_countries = set()
        current_countries = self.geo_data.get('_countries', set())

        for attack in recent_attacks[-10:]:  # Check last 10 attacks
            ip = attack.get('ip')
            if ip:
                location = self.get_ip_location(ip)
                country = location['country']
                if country != 'Unknown' and country not in current_countries:
                    new_countries.add(country)

        if new_countries:
            self.geo_data['_countries'] = current_countries | new_countries
            for country in new_countries:
                self.send_alert(
                    alert_type='new_country',
                    severity='info',
                    message=f"New attacking country detected: {country}",
                    data={'country': country}
                )

    def generate_charts_data(self):
        """Generate data for charts"""
        charts = {}

        try:
            # Attacks over time chart
            if self.attack_stats.get('by_hour'):
                hours = list(self.attack_stats['by_hour'].keys())
                counts = list(self.attack_stats['by_hour'].values())

                charts['attacks_over_time'] = {
                    'labels': hours,
                    'datasets': [{
                        'label': 'SSH Attacks per hour',
                        'data': counts,
                        'borderColor': '#4ecdc4',  # SSH color
                        'backgroundColor': 'rgba(78, 205, 196, 0.1)',
                        'fill': True
                    }]
                }

            # Attacks by country chart
            if self.attack_stats.get('by_country'):
                countries = list(self.attack_stats['by_country'].keys())
                counts = list(self.attack_stats['by_country'].values())

                charts['attacks_by_country'] = {
                    'labels': countries,
                    'datasets': [{
                        'label': 'SSH Attacks',
                        'data': counts,
                        'backgroundColor': [
                            '#4ecdc4', '#45b7d1', '#96ceb4', '#ff6b6b',
                            '#ffeaa7', '#ddaa44', '#95e1d3', '#f38181'
                        ]
                    }]
                }

            # Service distribution chart (SSH only now)
            if self.attack_stats.get('basic'):
                basic_stats = self.attack_stats['basic']
                services = ['SSH']
                counts = [basic_stats.get('ssh_attacks', 0)]

                charts['service_distribution'] = {
                    'labels': services,
                    'datasets': [{
                        'label': 'SSH Attacks',
                        'data': counts,
                        'backgroundColor': ['#4ecdc4']
                    }]
                }

        except Exception as e:
            print(f"[!] Error generating charts: {e}")

        return charts

    def setup_routes(self):
        """Setup Flask routes"""

        @self.app.route('/')
        def index():
            """Main dashboard"""
            stats = self.attack_stats.get('basic', {})
            recent = self.recent_attacks[-10:] if self.recent_attacks else []
            alerts = [a for a in self.alerts if not a['acknowledged']][-5:]

            return render_template('index.html',
                                   stats=stats,
                                   recent_attacks=recent,
                                   alerts=alerts,
                                   title="SSH Honeypot Dashboard")

        @self.app.route('/attacks')
        def attacks():
            """Attack log view"""
            page = int(request.args.get('page', 1))
            per_page = 50

            all_attacks = []
            if self.attack_monitor:
                all_attacks = self.attack_monitor.get_recent_attacks(
                    minutes=1440)  # 24 hours

            # Pagination
            total = len(all_attacks)
            start = (page - 1) * per_page
            end = start + per_page
            attacks_page = all_attacks[start:end]

            # Add location info
            for attack in attacks_page:
                ip = attack.get('ip')
                if ip:
                    attack['location'] = self.get_ip_location(ip)
                    attack['reputation'] = self.get_ip_reputation(ip)

            return render_template('attacks.html',
                                   attacks=attacks_page,
                                   page=page,
                                   per_page=per_page,
                                   total=total,
                                   title="SSH Attack Log")

        @self.app.route('/live')
        def live():
            """Live attack stream"""
            return render_template('live.html', title="Live SSH Attack Stream")

        @self.app.route('/stats')
        def stats():
            """Detailed statistics"""
            charts = self.generate_charts_data()

            # Get last updated time
            last_updated = dt.datetime.now().strftime('%H:%M:%S')

            return render_template('stats.html',
                                   stats=self.attack_stats,
                                   charts=charts,
                                   last_updated=last_updated,
                                   title="SSH Statistics & Charts")

        @self.app.route('/alerts')
        def alerts_view():
            """Alerts management"""
            return render_template('alerts.html',
                                   alerts=self.alerts,
                                   title="SSH Alerts")

        @self.app.route('/export')
        def export():
            """Export data page"""
            today = dt.date.today()
            yesterday = today - dt.timedelta(days=1)
            return render_template('export.html',
                                   title="Export SSH Data",
                                   today=today.isoformat(),
                                   yesterday=yesterday.isoformat())

        @self.app.route('/api/stats')
        def api_stats():
            """API endpoint for detailed statistics"""
            try:
                days = int(request.args.get('days', 7))

                # Get attacks based on days parameter
                recent = []
                if self.attack_monitor:
                    minutes = days * 1440 if days > 0 else 525600  # 1 year if "all time"
                    recent = self.attack_monitor.get_recent_attacks(
                        minutes=minutes)

                # Calculate statistics
                total_attacks = len(recent)
                ssh_attacks = total_attacks  # All attacks are SSH now

                # Unique IPs
                ips = [a.get('ip') for a in recent if a.get('ip')]
                unique_ips = len(set(ips))

                # Top attackers
                ip_counter = Counter(ips)
                top_attackers = []
                for ip, count in ip_counter.most_common(10):
                    location = self.get_ip_location(ip)
                    top_attackers.append({
                        'ip': ip,
                        'country': location['country'],
                        'country_code': location.get('country_code', 'xx'),
                        'ssh_attacks': count,
                        'total': count
                    })

                # Common usernames
                usernames = Counter([a.get('username')
                                    for a in recent if a.get('username')])

                # Attacks by country
                countries = Counter()
                for attack in recent:
                    ip = attack.get('ip')
                    if ip:
                        location = self.get_ip_location(ip)
                        countries[location['country']] += 1

                country_list = []
                total_countries = sum(countries.values())
                for country, count in countries.most_common(5):
                    percentage = (count / total_countries *
                                  100) if total_countries > 0 else 0
                    country_list.append({
                        'name': country if country != 'Unknown' else 'Unknown Location',
                        'count': count,
                        'percentage': round(percentage, 1)
                    })

                # Hourly analysis
                hourly_counts = defaultdict(int)
                for attack in recent:
                    try:
                        timestamp_str = attack['timestamp']
                        if 'Z' in timestamp_str:
                            timestamp_str = timestamp_str.replace(
                                'Z', '+00:00')
                        timestamp = dt.datetime.fromisoformat(timestamp_str)
                        hour = timestamp.hour
                        hourly_counts[hour] += 1
                    except (KeyError, ValueError):
                        continue

                # Find peak hour
                if hourly_counts:
                    peak_hour = max(hourly_counts.items(),
                                    key=lambda x: x[1])[0]
                else:
                    peak_hour = 0

                # Generate timeline data (last 7 days)
                timeline_data = defaultdict(lambda: {'ssh': 0})
                today = dt.date.today()
                for i in range(7):
                    day = today - dt.timedelta(days=i)
                    timeline_data[day.strftime('%Y-%m-%d')] = {'ssh': 0}

                for attack in recent[-500:]:  # Last 500 attacks for timeline
                    try:
                        timestamp_str = attack['timestamp']
                        if 'Z' in timestamp_str:
                            timestamp_str = timestamp_str.replace(
                                'Z', '+00:00')
                        timestamp = dt.datetime.fromisoformat(timestamp_str)
                        day_key = timestamp.strftime('%Y-%m-%d')
                        if day_key in timeline_data:
                            timeline_data[day_key]['ssh'] += 1
                    except (KeyError, ValueError):
                        continue

                timeline_labels = sorted(timeline_data.keys())[-7:]
                timeline_ssh = [timeline_data[day]['ssh']
                                for day in timeline_labels]

                return jsonify({
                    'total_attacks': total_attacks,
                    'ssh_attacks': ssh_attacks,
                    'unique_attackers': unique_ips,
                    'trend': 0,
                    'top_country': country_list[0]['name'] if country_list else 'Unknown',
                    'top_attackers': top_attackers,
                    'common_usernames': [[k, v] for k, v in usernames.most_common(10)],
                    'countries': country_list,
                    'hourly': {
                        'peak_hour': f"{peak_hour:02d}:00",
                        'average': total_attacks / (days * 24) if days > 0 else 0,
                        'frequency': f"{(total_attacks / (days * 24 * 60)):.1f}/min" if days > 0 else "0/min"
                    },
                    'charts': {
                        'timeline_labels': timeline_labels,
                        'timeline_ssh': timeline_ssh,
                        'timeline_web': [0] * 7,  # Empty for web
                        'distribution_ssh': ssh_attacks,
                        'distribution_web': 0,  # Zero web attacks
                        'distribution_other': 0,
                        'hourly_labels': [f"{h:02d}:00" for h in range(24)],
                        'hourly_data': [hourly_counts[h] for h in range(24)]
                    }
                })

            except Exception as e:
                print(f"[!] Error in api_stats: {e}")
                return jsonify({'error': str(e)}), 500

        @self.app.route('/api/attacks')
        def api_attacks():
            """API endpoint for attacks"""
            limit = int(request.args.get('limit', 50))
            offset = int(request.args.get('offset', 0))

            attacks = self.recent_attacks[offset:offset+limit]
            for attack in attacks:
                ip = attack.get('ip')
                if ip:
                    attack['location'] = self.get_ip_location(ip)

            return jsonify({
                'attacks': attacks,
                'total': len(self.recent_attacks),
                'offset': offset,
                'limit': limit
            })

        @self.app.route('/api/alerts')
        def api_alerts():
            """API endpoint for alerts"""
            acknowledged = request.args.get(
                'acknowledged', 'false').lower() == 'true'
            filtered = [
                a for a in self.alerts if a['acknowledged'] == acknowledged]
            return jsonify(filtered)

        @self.app.route('/api/alert/acknowledge/<alert_id>', methods=['POST'])
        def acknowledge_alert(alert_id):
            """Acknowledge an alert"""
            for alert in self.alerts:
                if alert['id'] == alert_id:
                    alert['acknowledged'] = True
                    self.socketio.emit('alert_acknowledged', {'id': alert_id})
                    return jsonify({'success': True})
            return jsonify({'success': False, 'error': 'Alert not found'}), 404

        @self.app.route('/api/ip/<ip_address>')
        def api_ip_info(ip_address):
            """Get detailed IP information"""
            location = self.get_ip_location(ip_address)
            reputation = self.get_ip_reputation(ip_address)

            # Get attacks from this IP
            ip_attacks = []
            if self.attack_monitor:
                all_attacks = self.attack_monitor.get_recent_attacks(
                    minutes=1440)
                ip_attacks = [
                    a for a in all_attacks if a.get('ip') == ip_address]

            return jsonify({
                'ip': ip_address,
                'location': location,
                'reputation': reputation,
                'attacks': ip_attacks[:20],  # Last 20 attacks
                'attack_count': len(ip_attacks)
            })

        @self.app.route('/api/export/preview')
        def api_export_preview():
            """Preview export data"""
            preview_data = []
            if self.attack_monitor:
                attacks = self.attack_monitor.get_recent_attacks(
                    minutes=1440)  # 24 hours
                for attack in attacks[:10]:  # First 10 for preview
                    preview_data.append({
                        'timestamp': attack.get('timestamp', ''),
                        'ip': attack.get('ip', ''),
                        'service': 'ssh',  # All attacks are SSH
                        'username': attack.get('username', ''),
                        'location': self.get_ip_location(attack.get('ip', '')) if attack.get('ip') else {}
                    })

            return jsonify(preview_data)

        @self.app.route('/api/export/csv')
        def api_export_csv():
            """Export data as CSV"""
            import csv
            from io import StringIO

            si = StringIO()
            cw = csv.writer(si)
            cw.writerow(['timestamp', 'ip', 'service', 'username',
                        'password_attempted', 'country'])

            if self.attack_monitor:
                attacks = self.attack_monitor.get_recent_attacks(minutes=1440)
                for attack in attacks[:100]:  # First 100
                    location = self.get_ip_location(attack.get('ip', '')) if attack.get(
                        'ip') else {'country': 'Unknown'}
                    cw.writerow([
                        attack.get('timestamp', ''),
                        attack.get('ip', ''),
                        'ssh',
                        attack.get('username', ''),
                        'yes' if attack.get('status') in [
                            'failed_password', 'invalid_user'] else 'no',
                        location.get('country', 'Unknown')
                    ])

            output = si.getvalue()
            return Response(
                output,
                mimetype="text/csv",
                headers={
                    "Content-disposition": "attachment; filename=ssh-honeypot-attacks.csv"}
            )

        @self.app.route('/api/export/json')
        def api_export_json():
            """Export data as JSON"""
            export_data = []
            if self.attack_monitor:
                attacks = self.attack_monitor.get_recent_attacks(minutes=1440)
                for attack in attacks[:100]:  # First 100
                    attack_copy = attack.copy()
                    if attack.get('ip'):
                        attack_copy['location'] = self.get_ip_location(
                            attack['ip'])
                    # Ensure service is set to SSH
                    attack_copy['service'] = 'ssh'
                    export_data.append(attack_copy)

            return jsonify(export_data)

    def setup_socketio_events(self):
        """Setup SocketIO event handlers"""

        @self.socketio.on('connect')
        def handle_connect():
            print(f"[+] Client connected: {request.sid}")
            emit('connected', {
                 'message': 'Connected to SSH honeypot dashboard'})

            # Send initial data
            emit('stats_update', self.attack_stats)
            emit('recent_attacks', self.recent_attacks[-10:])

            if self.alerts:
                unacknowledged = [
                    a for a in self.alerts if not a['acknowledged']]
                emit('alerts_update', unacknowledged[-5:])

        @self.socketio.on('request_stats')
        def handle_stats_request():
            emit('stats_update', self.attack_stats)

        @self.socketio.on('request_attacks')
        def handle_attacks_request():
            emit('recent_attacks', self.recent_attacks[-10:])

        @self.socketio.on('acknowledge_alert')
        def handle_acknowledge_alert(data):
            alert_id = data.get('alert_id')
            for alert in self.alerts:
                if alert['id'] == alert_id:
                    alert['acknowledged'] = True
                    emit('alert_acknowledged', {
                         'id': alert_id}, broadcast=True)
                    break

    def start_background_tasks(self):
        """Start background update tasks"""
        # Start update thread
        self.update_thread = threading.Thread(
            target=self.update_loop, daemon=True)
        self.update_thread.start()

    def update_loop(self):
        """Main update loop"""
        stats_update_interval = getattr(Config, 'STATS_UPDATE_INTERVAL', 10)

        while self.running:
            try:
                self.update_stats()
                time.sleep(stats_update_interval)
            except Exception as e:
                print(f"[!] Error in update loop: {e}")
                time.sleep(5)

    def run(self):
        """Run the dashboard"""
        print("\n" + "="*60)
        print("🔥 SSH HONEYPOT WEB DASHBOARD")
        print("="*60)
        host = getattr(Config, 'DASHBOARD_HOST', '0.0.0.0')
        port = getattr(Config, 'DASHBOARD_PORT', 5000)
        print(f"Dashboard URL: http://{host}:{port}")
        print(f"Live Stream: http://{host}:{port}/live")
        print(f"API Base: http://{host}:{port}/api/")
        print("="*60)

        try:
            self.socketio.run(self.app,
                              host=host,
                              port=port,
                              debug=getattr(Config, 'DEBUG', False),
                              allow_unsafe_werkzeug=True)
        except KeyboardInterrupt:
            print("\n[*] Shutting down dashboard...")
            self.running = False
            self.scheduler.shutdown()


if __name__ == "__main__":
    dashboard = HoneypotDashboard()
    dashboard.run()
