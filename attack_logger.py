# attack_logger.py
import json
import os
from datetime import datetime

JSON_LOG_FILE = 'attacks.json'

def log_attack(ip, username, password, honeypot_type='http', user_agent='Unknown'):
    """Enregistre une attaque dans le fichier JSON"""
    
    # Détecte si c'est un bot
    is_bot = False
    if user_agent:
        bot_indicators = ['bot', 'crawler', 'spider', 'scanner', 'python-requests', 'curl', 'wget']
        is_bot = any(indicator in user_agent.lower() for indicator in bot_indicators)
    
    # Score de menace simple
    threat_score = 0
    
    # Usernames courants
    common_users = ['admin', 'root', 'administrator', 'test', 'user', 'wp-admin']
    if username.lower() in common_users:
        threat_score += 25
    
    # Passwords courants
    common_passwords = ['123456', 'password', 'admin', 'root', 'test', '123456789', 'qwerty']
    if password.lower() in common_passwords:
        threat_score += 25
    
    # Bot detection
    if is_bot:
        threat_score += 20
    
    # Tor detection
    if 'tor' in user_agent.lower() or '.onion' in user_agent:
        threat_score += 30
    
    # Détermine le niveau de menace
    if threat_score >= 70:
        threat_level = "CRITICAL"
    elif threat_score >= 50:
        threat_level = "HIGH"
    elif threat_score >= 30:
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"
    
    # Crée l'objet d'attaque
    attack_data = {
        'timestamp': datetime.now().isoformat(),
        'ip': ip,
        'username': username,
        'password': password,
        'user_agent': user_agent[:100] if user_agent else 'Unknown',  # Limite à 100 caractères
        'is_bot': is_bot,
        'threat_score': threat_score,
        'threat_level': threat_level,
        'honeypot_type': honeypot_type
    }
    
    try:
        # Lis les attaques existantes
        existing_data = []
        if os.path.exists(JSON_LOG_FILE):
            with open(JSON_LOG_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        existing_data.append(json.loads(line))
        
        # Ajoute la nouvelle attaque
        existing_data.append(attack_data)
        
        # Écrit tout dans le fichier (garde seulement les 200 dernières)
        with open(JSON_LOG_FILE, 'w', encoding='utf-8') as f:
            for attack in existing_data[-200:]:
                f.write(json.dumps(attack) + '\n')
        
        print(f"[+] Attack logged: {ip} -> {username}:{password} [{threat_level}]")
        return True
        
    except Exception as e:
        print(f"[!] Failed to log attack: {e}")
        return False

def get_recent_attacks(limit=50):
    """Récupère les attaques récentes"""
    attacks = []
    try:
        if os.path.exists(JSON_LOG_FILE):
            with open(JSON_LOG_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        attacks.append(json.loads(line))
    except Exception as e:
        print(f"[!] Error reading attacks: {e}")
    
    # Retourne les plus récentes en premier
    attacks.reverse()
    return attacks[:limit]

def get_stats():
    """Calcule les statistiques"""
    attacks = get_recent_attacks(1000)  # 1000 dernières attaques
    
    if not attacks:
        return {
            'total': 0,
            'unique_ips': 0,
            'high_threats': 0,
            'bot_count': 0
        }
    
    unique_ips = len(set(a['ip'] for a in attacks))
    high_threats = len([a for a in attacks if a['threat_level'] in ['HIGH', 'CRITICAL']])
    bot_count = len([a for a in attacks if a.get('is_bot', False)])
    
    # Compte par username
    username_counter = {}
    for a in attacks:
        user = a['username']
        username_counter[user] = username_counter.get(user, 0) + 1
    
    top_users = sorted(username_counter.items(), key=lambda x: x[1], reverse=True)[:5]
    
    return {
        'total': len(attacks),
        'unique_ips': unique_ips,
        'high_threats': high_threats,
        'bot_count': bot_count,
        'top_users': top_users,
        'last_attacks': attacks[:10]  # 10 plus récentes
    }

if __name__ == "__main__":
    # Test du logger
    test_ip = "192.168.1.100"
    test_user = "admin"
    test_pass = "password123"
    
    print("Testing attack logger...")
    log_attack(test_ip, test_user, test_pass, 'http', 'Mozilla/5.0 Test Browser')
    
    stats = get_stats()
    print(f"Stats: {stats}")