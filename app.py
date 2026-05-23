from flask import Flask, render_template, request, redirect, session
from flask_bcrypt import Bcrypt
import sqlite3
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'secretkey'

bcrypt = Bcrypt(app)

# Database setup
conn = sqlite3.connect('users.db', check_same_thread=False)
cursor = conn.cursor()

# Users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
''')

# Login logs table
cursor.execute('''
CREATE TABLE IF NOT EXISTS login_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    ip_address TEXT,
    status TEXT,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

# Threat logs table
cursor.execute('''
CREATE TABLE IF NOT EXISTS threat_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    threat_level TEXT,
    reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

# Risk scores table
cursor.execute('''
CREATE TABLE IF NOT EXISTS risk_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    risk_score INTEGER,
    risk_level TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

# Blocked users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS blocked_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    blocked_until TIMESTAMP
)
''')

conn.commit()

# Home Route
@app.route('/')
def home():
    return redirect('/login')

# Register Route
@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            cursor.execute(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                (username, hashed_password)
            )

            conn.commit()

            return redirect('/login')

        except:
            return 'Username already exists!'

    return render_template('register.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        # Check blocked users
        cursor.execute(
            '''
            SELECT blocked_until
            FROM blocked_users
            WHERE username = ?
            ''',
            (username,)
        )

        blocked_user = cursor.fetchone()

        if blocked_user:

            blocked_until = datetime.fromisoformat(blocked_user[0])

            if datetime.now() < blocked_until:
                return f'Account blocked until {blocked_until}'

        ip_address = request.remote_addr

        cursor.execute(
            'SELECT * FROM users WHERE username = ?',
            (username,)
        )

        user = cursor.fetchone()

        # Successful login
        if user:

            stored_password = user[2]

            if bcrypt.check_password_hash(stored_password, password):

                cursor.execute(
                    '''
                    INSERT INTO login_logs
                    (username, ip_address, status)
                    VALUES (?, ?, ?)
                    ''',
                    (username, ip_address, 'SUCCESS')
                )

                conn.commit()

                session['user'] = username

                return redirect('/dashboard')

        # Failed login
        cursor.execute(
            '''
            INSERT INTO login_logs
            (username, ip_address, status)
            VALUES (?, ?, ?)
            ''',
            (username, ip_address, 'FAILED')
        )

        conn.commit()

        # Count failed attempts
        cursor.execute(
            '''
            SELECT COUNT(*)
            FROM login_logs
            WHERE username = ?
            AND status = 'FAILED'
            ''',
            (username,)
        )

        failed_attempts = cursor.fetchone()[0]

        # AI Risk Score
        risk_score = failed_attempts * 20

        current_hour = datetime.now().hour

        if current_hour >= 12:
            risk_score += 10

        # Risk level
        risk_level = 'LOW'

        if risk_score >= 70:
            risk_level = 'HIGH'

        elif risk_score >= 40:
            risk_level = 'MEDIUM'

        # Save risk score
        cursor.execute(
            '''
            INSERT INTO risk_scores
            (username, risk_score, risk_level)
            VALUES (?, ?, ?)
            ''',
            (
                username,
                risk_score,
                risk_level
            )
        )

        conn.commit()

        # Threat detection
        if risk_score >= 70:

            cursor.execute(
                '''
                INSERT INTO threat_logs
                (username, threat_level, reason)
                VALUES (?, ?, ?)
                ''',
                (
                    username,
                    'HIGH',
                    'Multiple failed login attempts'
                )
            )

            conn.commit()

            # Block user for 5 minutes
            blocked_until = datetime.now() + timedelta(minutes=5)

            cursor.execute(
                '''
                INSERT INTO blocked_users
                (username, blocked_until)
                VALUES (?, ?)
                ''',
                (
                    username,
                    blocked_until.isoformat()
                )
            )

            conn.commit()

            return f'Account blocked until {blocked_until}'

        return 'Invalid Username or Password'

    return render_template('login.html')

# Dashboard Route
@app.route('/dashboard')
def dashboard():

    # Login logs
    cursor.execute(
        '''
        SELECT username, ip_address, status, login_time
        FROM login_logs
        ORDER BY id DESC
        '''
    )

    logs = cursor.fetchall()

    # Threat logs
    cursor.execute(
        '''
        SELECT username, threat_level, reason, created_at
        FROM threat_logs
        ORDER BY id DESC
        '''
    )

    threats = cursor.fetchall()

    # Risk scores
    cursor.execute(
        '''
        SELECT username, risk_score, risk_level, created_at
        FROM risk_scores
        ORDER BY id DESC
        '''
    )

    risks = cursor.fetchall()

    return render_template(
        'dashboard.html',
        logs=logs,
        threats=threats,
        risks=risks
    )

# Logout Route
@app.route('/logout')
def logout():

    session.pop('user', None)

    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)