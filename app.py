from flask import Flask, request, jsonify, render_template, redirect, url_for
from datetime import datetime
import sqlite3
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import requests
import os

app = Flask(__name__)
CORS(app, resources={r"/log": {"origins": "*"}})  # Allow CORS only for the log route

# Initialize the Limiter (in-memory storage for rate limiting)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# Initialize database
def init_db():
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    
    # Add the 'name' column if it doesn't exist
    try:
        cursor.execute('ALTER TABLE user_logs ADD COLUMN name TEXT')
    except sqlite3.OperationalError:
        pass  # This error occurs if the column already exists

    # Ensure the rest of the table has all necessary columns
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            codeforces_id TEXT NOT NULL,
            division TEXT NOT NULL,
            rating INTEGER,
            ip_address TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')
    
    conn.commit()
    conn.close()

# Fetch rating from Codeforces API
def fetch_rating(codeforces_id):
    api_url = f"https://codeforces.com/api/user.info?handles={codeforces_id}"
    response = requests.get(api_url)
    data = response.json()
    
    if 'result' in data:
        return data['result'][0].get('rating', 'Unrated')
    return 'Unrated'

# Function to get user's IP address
def get_user_ip():
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
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
    user_name = request.json.get('name')
    user_handle = request.json.get('codeforces_id')
    user_division = request.json.get('division')
    
    if not user_name or not user_handle or not user_division or not is_valid_handle(user_handle):
        return jsonify({'status': 'error', 'message': 'Invalid input'}), 400
    
    ip_address = get_user_ip()
    timestamp = datetime.now().isoformat()
    
    # Fetch rating from Codeforces API
    rating = fetch_rating(user_handle)

    # Save the data in the database
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO user_logs (name, codeforces_id, division, rating, ip_address, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (user_name, user_handle, user_division, rating, ip_address, timestamp))
    conn.commit()
    conn.close()

    return jsonify({
        'status': 'success',
        'message': f'Logged presence for {user_handle} with rating {rating}',
        'ip': ip_address,
        'timestamp': timestamp
    })

# Route to get all logs
@app.route('/all-logs', methods=['GET'])
def get_all_logs():
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute('SELECT name, codeforces_id, division, rating, ip_address, timestamp FROM user_logs')
    logs = cursor.fetchall()
    conn.close()

    return render_template('all_logs.html', logs=logs)

# Route to clear all logs
@app.route('/clear-logs', methods=['POST'])
def clear_logs():
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM user_logs')
    conn.commit()
    conn.close()
    return redirect(url_for('get_all_logs'))

if __name__ == '__main__':
    init_db()  # Initialize the database when the app starts
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
