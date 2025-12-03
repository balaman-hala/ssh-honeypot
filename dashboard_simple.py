# dashboard_simple.py - VERSION AMÉLIORÉE
from flask import Flask, jsonify
import json
import os
from collections import Counter
from datetime import datetime

app = Flask(__name__)

# Template HTML plus joli
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Honeypot Dashboard</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        
        .header {
            background: rgba(255, 255, 255, 0.95);
            padding: 30px;
            border-radius: 15px;
            margin-bottom: 30px;
            text-align: center;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
        }
        
        .header h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 2.5em;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.95);
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s;
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
        }
        
        .stat-card h3 {
            color: #666;
            font-size: 1em;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .stat-card h1 {
            color: #333;
            font-size: 2.5em;
            font-weight: bold;
        }
        
        .attack-list {
            background: rgba(255, 255, 255, 0.95);
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }
        
        .attack-item {
            display: grid;
            grid-template-columns: 100px 150px 1fr 100px 80px;
            gap: 15px;
            padding: 12px;
            border-bottom: 1px solid #eee;
            align-items: center;
        }
        
        .attack-item.header {
            font-weight: bold;
            background: #f8f9fa;
            border-radius: 5px;
            margin-bottom: 10px;
        }
        
        .critical { color: #dc3545; font-weight: bold; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        
        .bot-badge {
            background: #6f42c1;
            color: white;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.8em;
        }
        
        .update-time {
            text-align: center;
            color: white;
            margin-top: 20px;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🐝 Honeypot Dashboard</h1>
        <p>Real-time monitoring of attack attempts</p>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <h3>Total Attacks</h3>
            <h1 id="total">0</h1>
        </div>
        <div class="stat-card">
            <h3>Unique IPs</h3>
            <h1 id="unique">0</h1>
        </div>
        <div class="stat-card">
            <h3>High Threats</h3>
            <h1 id="high" class="high">0</h1>
        </div>
        <div class="stat-card">
            <h3>Bots Detected</h3>
            <h1 id="bots">0</h1>
        </div>
    </div>
    
    <div class="attack-list">
        <h2 style="margin-bottom: 20px; color: #333;">Recent Attacks</h2>
        <div class="attack-item header">
            <div>Time</div>
            <div>IP Address</div>
            <div>Credentials</div>
            <div>Threat</div>
            <div>Type</div>
        </div>
        <div id="attacks">
            <p>Loading attacks...</p>
        </div>
    </div>
    
    <div class="update-time">
        Last updated: <span id="updateTime">--:--:--</span>
        <p>Auto-refreshes every 10 seconds</p>
    </div>
    
    <script>
        function loadAttacks() {
            fetch('/api/attacks')
                .then(response => response.json())
                .then(data => {
                    // Update stats
                    document.getElementById('total').textContent = data.total;
                    document.getElementById('unique').textContent = data.unique_ips;
                    document.getElementById('high').textContent = data.high_threats;
                    document.getElementById('bots').textContent = data.bot_count;
                    
                    // Update attack list
                    const attacksDiv = document.getElementById('attacks');
                    let html = '';
                    
                    data.attacks.forEach(attack => {
                        // Format time
                        const time = attack.timestamp.substring(11, 19);
                        
                        // Threat class
                        const threatClass = attack.threat_level.toLowerCase();
                        
                        html += `
                            <div class="attack-item">
                                <div>${time}</div>
                                <div><code>${attack.ip}</code></div>
                                <div>${attack.username}:${attack.password}</div>
                                <div class="${threatClass}">${attack.threat_level}</div>
                                <div>${attack.is_bot ? '<span class="bot-badge">BOT</span>' : 'Human'}</div>
                            </div>
                        `;
                    });
                    
                    attacksDiv.innerHTML = html || '<p>No attacks recorded yet.</p>';
                    
                    // Update time
                    const now = new Date();
                    document.getElementById('updateTime').textContent = 
                        now.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'});
                })
                .catch(error => {
                    console.error('Error:', error);
                    document.getElementById('attacks').innerHTML = '<p>Error loading data.</p>';
                });
        }
        
        // Load attacks immediately
        loadAttacks();
        
        // Auto-refresh every 10 seconds
        setInterval(loadAttacks, 10000);
    </script>
</body>
</html>
'''

def load_attack_data():
    """Charge les données d'attaque depuis le fichier JSON"""
    attacks = []
    try:
        if os.path.exists('attacks.json'):
            with open('attacks.json', 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        attacks.append(json.loads(line))
    except Exception as e:
        print(f"Error loading attacks: {e}")
    
    return attacks

@app.route('/')
def dashboard():
    """Page principale du dashboard"""
    return HTML_TEMPLATE

@app.route('/api/attacks')
def api_attacks():
    """API qui renvoie les données d'attaque"""
    attacks = load_attack_data()
    
    if not attacks:
        return jsonify({
            'total': 0,
            'unique_ips': 0,
            'high_threats': 0,
            'bot_count': 0,
            'attacks': []
        })
    
    # Calcule les statistiques
    unique_ips = len(set(a['ip'] for a in attacks))
    
    # Compte les menaces élevées
    high_threats = len([a for a in attacks if a['threat_level'] in ['HIGH', 'CRITICAL']])
    
    # Compte les bots
    bot_count = len([a for a in attacks if a.get('is_bot', False)])
    
    # Trie par date (plus récent d'abord)
    attacks_sorted = sorted(attacks, key=lambda x: x['timestamp'], reverse=True)
    
    # Limite à 20 attaques
    recent_attacks = attacks_sorted[:20]
    
    return jsonify({
        'total': len(attacks),
        'unique_ips': unique_ips,
        'high_threats': high_threats,
        'bot_count': bot_count,
        'attacks': recent_attacks
    })

@app.route('/api/stats')
def api_stats():
    """API simple pour les statistiques"""
    attacks = load_attack_data()
    
    total = len(attacks)
    unique_ips = len(set(a['ip'] for a in attacks))
    
    # Compte par username
    username_counter = Counter()
    for attack in attacks:
        username_counter[attack['username']] += 1
    
    top_users = username_counter.most_common(5)
    
    return jsonify({
        'total_attacks': total,
        'unique_attackers': unique_ips,
        'top_usernames': [{'username': u, 'count': c} for u, c in top_users]
    })

if __name__ == '__main__':
    print("\n" + "="*50)
    print("📊 HONEYPOT DASHBOARD")
    print("="*50)
    print("🔗 Access: http://localhost:5001")
    print("📈 Real-time attack monitoring")
    print("🔄 Auto-refresh every 10 seconds")
    print("="*50 + "\n")
    
    app.run(debug=True, port=5001, host="0.0.0.0")