import os


class Config:
    # Flask settings (if you want a minimal web interface)
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'ssh-honeypot-key'
    DEBUG = False

    # Log settings
    LOG_DIR = 'logs'
    SSH_LOG_FILE = os.path.join(LOG_DIR, 'ssh_attacks.json')

    # Alert thresholds
    SSH_ALERT_THRESHOLD = 5  # Attempts per minute

    # Data retention
    DATA_RETENTION_DAYS = 30
