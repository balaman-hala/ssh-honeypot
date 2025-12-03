# web_honeypot.py
from flask import Flask, render_template, request
import time
import random
from attack_logger import log_attack

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('wp-admin.html')

@app.route('/wp-admin-login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    
    time.sleep(random.uniform(0.5, 1.5))
    
    print(f"Attack: {ip_address} - {username}:{password}")
    
    log_attack(
        ip=ip_address,
        username=username,
        password=password,
        honeypot_type='wordpress',
        user_agent=user_agent
    )
    
    return '''
    <div style="text-align: center; padding: 50px; font-family: Arial;">
        <h2 style="color: #dc3545;">❌ Access Denied</h2>
        <p>Invalid username or password.</p>
        <p><a href="/">← Try Again</a></p>
    </div>
    '''

if __name__ == '__main__':
    print("\n🚀 WordPress Honeypot starting on port 5000")
    print("🔗 Access at: http://localhost:5000\n")
    app.run(debug=True, port=5000, host="0.0.0.0")