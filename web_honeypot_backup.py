import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for

logging_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
#creating HTTP Logger
funnel_logger = logging.getLogger('HTTP Logger') #creating a logger named FunnelLogger
funnel_logger.setLevel(logging.INFO) #for general logging informations
funnel_handler = RotatingFileHandler('http_system.log', maxBytes=2000, backupCount=4) #send funnel logs to a file named system.log and rotate it if it reaches 2000bytes (we can keep up to 4 log files archived)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)



def web_honeypot(input_username="admin", input_password="password"):
    
    app = Flask(__name__)
    
    @app.route('/')
    
    def index():
        return render_template('wp-admin.html')
    
    @app.route('/wp-admin-login', methods=['POST'])
    
    def login():
        username = request.form['username']
        password = request.form['password']
        
        ip_address = request.remote_addr
        
        funnel_logger.info(f'Client with IP Address: {ip_address} entered\n Username: {username}, Password: {password}')
        if username == input_username and password == input_password:
            return "YAAAY?"
        else:
            return "Invalid username or password. Please try again."
    
    return app

def run_web_honeypot(port=5000, input_username="admin", input_password="password"):
    run_web_honeypot_app = web_honeypot(input_username, input_password)
    run_web_honeypot_app.run(debug=True, port=port, host="0.0.0.0")
    
    return run_web_honeypot_app


