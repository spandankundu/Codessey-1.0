from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from datetime import datetime
import sqlite3
import pytz  # For time zone conversion
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
import requests
import os
import base64  # Import base64 for image handling

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session management
CORS(app, resources={r"/log": {"origins": "*"}})

# Initialize the Limiter (in-memory storage for rate limiting)
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# Initialize database
def init_db():
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute(''' 
        CREATE TABLE IF NOT EXISTS user_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            participant_id TEXT NOT NULL,
            seat_number TEXT NOT NULL,
            codeforces_id TEXT NOT NULL,
            division TEXT NOT NULL,
            rating INTEGER,
            ip_address TEXT NOT NULL,
            photo BLOB,
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

# Convert timestamp to IST and format in 12-hour format
def get_ist_timestamp():
    ist = pytz.timezone('Asia/Kolkata')
    now = datetime.now(ist)
    return now.strftime("%Y-%m-%d %I:%M %p")  # 12-hour format

# Log user activity with rate limiting (60 requests per minute)
@app.route('/log', methods=['POST'])
@limiter.limit("60 per minute")
def log_user_activity():
    user_name = request.json.get('name')
    participant_id = request.json.get('participant_id')
    seat_number = request.json.get('seat_number')
    user_handle = request.json.get('codeforces_id')
    user_division = request.json.get('division')
    user_photo = request.json.get('photo')

    if not user_name or not user_handle or not user_division or not participant_id or not seat_number or not is_valid_handle(user_handle):
        return jsonify({'status': 'error', 'message': 'Invalid input'}), 400

    ip_address = get_user_ip()
    timestamp = get_ist_timestamp()

    # Fetch rating from Codeforces API
    rating = fetch_rating(user_handle)

    # Save the data in the database
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()

    # Store photo as binary data
    if user_photo.startswith("data:image/png;base64,"):
        user_photo = user_photo.split(",")[1]  # Remove the prefix
        user_photo = base64.b64decode(user_photo)  # Decode the base64 string

    cursor.execute(''' 
        INSERT INTO user_logs (name, participant_id, seat_number, codeforces_id, division, rating, ip_address, photo, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (user_name, participant_id, seat_number, user_handle, user_division, rating, ip_address, user_photo, timestamp))
    conn.commit()
    conn.close()

    # Redirect to Codeforces login page
    codeforces_login_url = f"https://codeforces.com/enter?back=contest"  # Adjust the URL as needed

    return jsonify({
        'status': 'success',
        'message': f'Logged presence for {user_handle} with rating {rating}',
        'ip': ip_address,
        'timestamp': timestamp,
        'redirect_url': codeforces_login_url  # Add redirect URL to response
    })

# Route to get all logs (protected)
@app.route('/all-logs', methods=['GET'])
def get_all_logs():
    if 'logged_in' not in session:
        return redirect(url_for('login'))  # Redirect to login if not authenticated

    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute('SELECT name, participant_id, seat_number, codeforces_id, division, rating, ip_address, photo, timestamp FROM user_logs')
    logs = cursor.fetchall()
    conn.close()

    return render_template('all_logs.html', logs=logs)

# Route to clear all logs (protected)
@app.route('/clear-logs', methods=['POST'])
def clear_logs():
    if 'logged_in' not in session:
        return redirect(url_for('login'))  # Redirect to login if not authenticated

    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM user_logs')
    conn.commit()
    conn.close()
    return redirect(url_for('get_all_logs'))

# Route to log in
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        password = request.form['password']
        if password == 'codessey':  # Replace with your desired password
            session['logged_in'] = True
            return redirect(url_for('get_all_logs'))
        else:
            return "Invalid password", 403
    return render_template('login.html')

# Custom filter for base64 encoding
@app.template_filter('b64encode')
def b64encode(data):
    if data:
        return base64.b64encode(data).decode('utf-8')
    return None

# Home route
@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    init_db()  # Initialize the database when the app starts
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
