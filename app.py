from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
import os
from urllib.parse import urlparse
from telegram import Bot
import logging
import requests
from threading import Thread
from functools import wraps
import re
from collections import defaultdict
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Telegram Configuration
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID')

def send_telegram_message(message):
    """Send message to Telegram channel using requests"""
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        try:
            # Run in background thread to avoid blocking
            def send_async():
                url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
                payload = {
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": message,
                    "parse_mode": "HTML"
                }
                try:
                    response = requests.post(url, json=payload, timeout=5)
                    if not response.ok:
                        logger.error(f"Telegram API error: {response.text}")
                except Exception as e:
                    logger.error(f"Failed to send Telegram message: {e}")

            Thread(target=send_async).start()
        except Exception as e:
            logger.error(f"Failed to start Telegram message thread: {e}")

# Database configuration
database_url = os.environ.get('DATABASE_URL')
if database_url:
    # Handle Render's postgres:// vs postgresql:// difference
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    # Local SQLite database as fallback
    db_path = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'database', 'fifa_rivals.db')
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Get download URL from environment variable
DOWNLOAD_URL = os.environ.get('DOWNLOAD_URL')

# Get admin credentials from environment variables
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'fifa2024')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'admin_login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Visit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_mobile = db.Column(db.Boolean, nullable=False)
    ip_address = db.Column(db.String(45))

class Download(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Bot protection configurations
BLOCKED_IPS = set()  # This will now stay empty

def is_bot(user_agent):
    """Check if user agent string matches known bot patterns"""
    # Remove all bot detection - allow all user agents
    return False

def bot_protection(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Remove IP blocking and simply pass through all requests
        return f(*args, **kwargs)
    return decorated_function

# Constants for visit tracking (5 minute window)
VISIT_WINDOW = 300  # 5 minutes in seconds
visit_timestamps = defaultdict(list)

def is_recent_visit(ip):
    """Check if IP has visited recently (within 5 minutes)"""
    now = datetime.now()
    visit_timestamps[ip] = [t for t in visit_timestamps[ip] if now - t < timedelta(seconds=VISIT_WINDOW)]
    return len(visit_timestamps[ip]) > 0

# Initialize GeoIP reader
geo_reader = None
try:
    import geoip2.database
    import geoip2.errors
    # Try multiple common locations for the GeoIP database
    possible_paths = [
        'GeoLite2-Country.mmdb',
        'database/GeoLite2-Country.mmdb',
        os.path.join(os.path.dirname(__file__), 'GeoLite2-Country.mmdb'),
        os.path.join(os.path.dirname(__file__), 'database', 'GeoLite2-Country.mmdb')
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            geo_reader = geoip2.database.Reader(path)
            logger.info(f"GeoIP database found at: {path}")
            break
            
    if not geo_reader:
        logger.warning("GeoIP database not found in any of the expected locations")
except ImportError:
    logger.warning("GeoIP2 module not installed. Country detection will be disabled.")
except Exception as e:
    logger.warning(f"Error initializing GeoIP: {str(e)}")

def get_country_from_ip(ip):
    """Get country from IP using GeoIP2 with fallback"""
    if not geo_reader:
        return "Unknown"
    try:
        response = geo_reader.country(ip)
        return response.country.name
    except:
        # Fallback: Try to determine region from IP range
        ip_parts = ip.split('.')
        if len(ip_parts) == 4:
            if ip_parts[0] in ['10', '172', '192', '127']:
                return 'Local Network'
        return "Unknown"

# Routes
@app.route('/')
@bot_protection
def index():
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    is_mobile = 'Mobile' in user_agent
    
    # Only track visit and send notification if it's not a recent visit
    if not is_recent_visit(ip_address):
        # Add timestamp for this visit
        visit_timestamps[ip_address].append(datetime.now())
        
        # Track visit in database
        new_visit = Visit(is_mobile=is_mobile, ip_address=ip_address)
        db.session.add(new_visit)
        db.session.commit()

        # Get country for the notification
        country = get_country_from_ip(ip_address)

        # Send Telegram notification with country
        message = (
            f"🌐 New Visit:\n"
            f"IP: {ip_address}\n"
            f"Country: {country}\n"
            f"Device: {'📱 Mobile' if is_mobile else '💻 Desktop'}\n"
            f"User Agent: {user_agent}"
        )
        send_telegram_message(message)
    
    return render_template('download.html')

@app.route('/track-download', methods=['POST'])
@bot_protection
def track_download():
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    country = get_country_from_ip(ip_address)
    
    # Generate unique filename with timestamp for better tracking
    timestamp = datetime.now().strftime('%m%d')
    unique_id = str(uuid.uuid4())[:6]
    unique_filename = f"v1_2_6_{timestamp}_{unique_id}.zip"
    
    new_download = Download(ip_address=ip_address)
    db.session.add(new_download)
    db.session.commit()

    # Send Telegram notification with country
    message = (
        f"⬇️ New Download:\n"
        f"IP: {ip_address}\n"
        f"Country: {country}\n"
        f"File: {unique_filename}\n"
        f"User Agent: {user_agent}"
    )
    send_telegram_message(message)
    
    return jsonify({
        'success': True, 
        'download_url': DOWNLOAD_URL,
        'filename': unique_filename
    })

@app.route('/admin/login', methods=['GET', 'POST'])
@bot_protection
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == password:  # In production, use proper password hashing
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        flash('Invalid credentials')
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    total_visits = Visit.query.count()
    total_downloads = Download.query.count()
    mobile_visits = Visit.query.filter_by(is_mobile=True).count()
    conversion_rate = (total_downloads / total_visits * 100) if total_visits > 0 else 0
    
    recent_activities = []
    recent_visits = Visit.query.order_by(Visit.timestamp.desc()).limit(5).all()
    recent_downloads = Download.query.order_by(Download.timestamp.desc()).limit(5).all()
    
    for visit in recent_visits:
        recent_activities.append({
            'type': 'Visit',
            'timestamp': visit.timestamp,
            'device': 'Mobile' if visit.is_mobile else 'Desktop'
        })
    
    for download in recent_downloads:
        recent_activities.append({
            'type': 'Download',
            'timestamp': download.timestamp
        })
    
    recent_activities.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return render_template('admin_dashboard.html',
                         total_visits=total_visits,
                         total_downloads=total_downloads,
                         mobile_visits=mobile_visits,
                         conversion_rate=round(conversion_rate, 1),
                         recent_activities=recent_activities[:10])

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('admin_login'))

def init_db():
    with app.app_context():
        db.create_all()
        # Create admin user if it doesn't exist
        if not User.query.filter_by(username=ADMIN_USERNAME).first():
            admin = User(username=ADMIN_USERNAME, password=ADMIN_PASSWORD)
            db.session.add(admin)
            db.session.commit()

# Initialize database tables and admin user on startup
init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000))) 
