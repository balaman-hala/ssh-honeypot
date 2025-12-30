#!/usr/bin/env python3
"""
CREATES BAIT FILES FOR REAL HONEYPOTS
"""
import os
import json
from datetime import datetime


class BaitFileCreator:
    def __init__(self):
        self.bait_dir = 'bait_files'
        os.makedirs(self.bait_dir, exist_ok=True)

    def create_ssh_bait_files(self):
        """Create bait files for SSH honeypot"""
        print("[*] Creating SSH bait files...")

        # Main secrets file
        secrets_content = """=== CONFIDENTIAL - PRODUCTION SERVER CREDENTIALS ===

DATABASE ACCESS:
===============
Host: 10.0.1.50:3306
Database: production_db
Username: prod_admin
Password: P@ssw0rd2024!

SSH KEYS FOR PRODUCTION:
========================
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtF3aXfZKe8vJZ1Q5LX9LJ7sKwN8Yqo6e9vLp7rTxJkLm8vH7
dNwZbM5rP4tq2X8yKj9nLm5vR2t8wQxX5sP9qKj3mN7vB2t8wQxX5sP9qKj3mN7
vB2t8wQxX5sP9qKj3mN7vB2t8wQxX5sP9qKj3mN7vB2t8wQxX5sP9qKj3mN7vB2
t8wQxX5sP9qKj3mN7vB2t8wQxX5sP9qKj3mN7vB2t8wQxX5sP9qKj3mN7vB2t8
wQxX5sP9qKj3mN7vB2t8wQxX5sP9qKj3mN7vB2t8wQxX5sP9qKj3mN7vB2t8wQx
-----END RSA PRIVATE KEY-----

API KEYS & TOKENS:
==================
Stripe Live Key: sk_live_51NfAk2SGFakeKey123456789
AWS Access Key: AKIAIOSFODNN7EXAMPLE
AWS Secret Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GitHub Token: ghp_FakeToken1234567890abcdef
Slack Webhook: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX

INTERNAL NETWORK:
=================
VPN Gateway: 10.0.1.1
Database Server: 10.0.1.50
Web Server: 10.0.1.100
File Server: 10.0.1.150
Backup Server: 10.0.1.200
"""

        with open(os.path.join(self.bait_dir, 'secrets.txt'), 'w') as f:
            f.write(secrets_content)

        # Config files
        configs = [
            ('ssh_config', 'Host production\n  HostName 10.0.1.100\n  User root\n  IdentityFile ~/.ssh/id_rsa_production'),
            ('.env', 'APP_ENV=production\nDB_PASSWORD=SuperSecret123!\nAPI_KEY=1234567890abcdef'),
            ('backup_script.sh', '#!/bin/bash\n# Backup script\n# Contains sensitive info'),
        ]

        for filename, content in configs:
            with open(os.path.join(self.bait_dir, filename), 'w') as f:
                f.write(content)

        print(f"[+] Created SSH bait files in {self.bait_dir}/")

    def create_wordpress_bait_files(self):
        """Create bait files for WordPress honeypot"""
        print("[*] Creating WordPress bait files...")

        wp_bait_dir = os.path.join(self.bait_dir, 'wordpress')
        os.makedirs(wp_bait_dir, exist_ok=True)

        # Fake wp-config.php
        wp_config = """<?php
// WordPress Configuration
define('DB_NAME', 'wordpress_prod');
define('DB_USER', 'wp_admin');
define('DB_PASSWORD', 'WpProdPass123!');
define('DB_HOST', '10.0.1.50');
define('DB_CHARSET', 'utf8mb4');

// API Keys
define('STRIPE_PUBLIC_KEY', 'pk_live_51NfAk2SGFakeKey123');
define('STRIPE_SECRET_KEY', 'sk_live_51NfAk2SGFakeKey456');
"""

        with open(os.path.join(wp_bait_dir, 'wp-config.php'), 'w') as f:
            f.write(wp_config)

        # Fake credentials file
        credentials = """# WordPress Admin
URL: http://company.com/wp-admin
Username: administrator
Password: AdminPass123!

# FTP Access
Host: ftp.company.com
Username: wp_ftp
Password: FtpPass456!

# Database
Host: 10.0.1.50:3306
Database: wordpress_prod
Username: wp_admin  
Password: DbPass789!
"""

        with open(os.path.join(wp_bait_dir, 'credentials.txt'), 'w') as f:
            f.write(credentials)

        print("[+] Created WordPress bait files")
