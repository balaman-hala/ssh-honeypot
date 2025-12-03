# dashboard_simple.py
from flask import Flask, jsonify
import json
import os

app = Flask(__name__)

@app.route('/')
def home():
    return '''
    <h1>Honeypot Dashboard</h1>
    <p><a href="/attacks">See Attacks</a></p>
    <p><a href="/stats">See Stats</a></p>
    '''

@app.route('/attacks')
def show_attacks():
    """Montre les attaques"""
    try:
        # Lis le fichier attacks.json
        with open('attacks.json', 'r') as f:
            lines = f.readlines()
        
        html = "<h2>Recent Attacks</h2><ul>"
        for line in lines[-10:]:  # 10 dernières
            attack = json.loads(line.strip())
            html += f'''
            <li>
                {attack['timestamp'][11:19]} | 
                {attack['ip']} | 
                {attack['username']}:{attack['password']} | 
                <strong>{attack['threat_level']}</strong>
            </li>
            '''
        html += "</ul><p><a href='/'>Back</a></p>"
        return html
        
    except Exception as e:
        return f"<p>Error: {e}</p><p>File exists: {os.path.exists('attacks.json')}</p>"

@app.route('/stats')
def show_stats():
    """Montre les statistiques"""
    try:
        with open('attacks.json', 'r') as f:
            attacks = [json.loads(line) for line in f if line.strip()]
        
        total = len(attacks)
        unique_ips = len(set(a['ip'] for a in attacks))
        
        html = f'''
        <h2>Statistics</h2>
        <p>Total Attacks: <strong>{total}</strong></p>
        <p>Unique IPs: <strong>{unique_ips}</strong></p>
        <p><a href='/'>Back</a></p>
        '''
        return html
        
    except Exception as e:
        return f"<p>No data yet: {e}</p>"

if __name__ == '__main__':
    print("Dashboard on http://localhost:5001")
    app.run(port=5001)