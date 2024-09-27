from flask import Flask, request, jsonify, render_template
from datetime import datetime
import sqlite3
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app, resources={r"/log": {"origins": "*"}})  # Allow CORS only for the log route

# Initialize the Limiter (in-memory storage for rate limiting)
limiter = Limiter(key_func=get_remote_address)

# Initialize the app with the Limiter
limiter.init_app(app)

# Initialize database
def init_db():
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            handle TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Function to get user's IP address
def get_user_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]  # Take the first IP address
    return request.remote_addr

# Input validation for Codeforces handle
def is_valid_handle(handle):
    return handle.isalnum() or ('_' in handle) or ('-' in handle)

# Route to serve the frontend portal
@app.route('/')
def home():
    return render_template('index.html')

# Log user activity with rate limiting (10 requests per minute)
@app.route('/log', methods=['POST'])
@limiter.limit("10 per minute")
def log_user_activity():
    user_handle = request.json.get('handle')
    
    if not user_handle or not is_valid_handle(user_handle):
        return jsonify({'status': 'error', 'message': 'Invalid handle format'}), 400
    
    ip_address = get_user_ip()
    timestamp = datetime.now().isoformat()

    # Save the data in the database
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO user_logs (handle, ip_address, timestamp)
        VALUES (?, ?, ?)
    ''', (user_handle, ip_address, timestamp))
    conn.commit()
    conn.close()

    return jsonify({
        'status': 'success',
        'message': f'Logged presence for {user_handle}',
        'ip': ip_address,
        'timestamp': timestamp
    })

# Route to get logs for a specific user
@app.route('/logs/<string:handle>', methods=['GET'])
def get_user_logs(handle):
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT handle, ip_address, timestamp FROM user_logs
        WHERE handle = ?
    ''', (handle,))
    logs = cursor.fetchall()
    conn.close()

    return jsonify({
        'status': 'success',
        'logs': logs
    })

# Route to get all logs and display them in a table format
@app.route('/all-logs', methods=['GET'])
def get_all_logs():
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute('SELECT handle, ip_address, timestamp FROM user_logs')
    logs = cursor.fetchall()
    conn.close()

    # Render the logs into the 'all_logs.html' template
    return render_template('all_logs.html', logs=logs)

if __name__ == '__main__':
    init_db()  # Initialize the database when the app starts
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
