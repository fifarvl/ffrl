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
WINDOWS_DOWNLOAD_URL = os.environ.get('WINDOWS_DOWNLOAD_URL')
ANDROID_DOWNLOAD_URL = os.environ.get('ANDROID_DOWNLOAD_URL')

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

class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_pattern = db.Column(db.String(45), nullable=False, unique=True)
    reason = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Bot protection configurations
BLOCKED_IPS = set()  # This will now stay empty

def is_bot(user_agent):
    """Check if user agent string matches known bot patterns"""
    if not user_agent:
        return True
        
    user_agent = user_agent.lower()
    
    # List of blocked bot user agents
    blocked_bots = [
        'twitterbot',
        'censysinspect',
        'telegrambot',
        'bot',
        'crawler',
        'spider',
        'curl',
        'wget',
        'python-requests',
        'python-urllib',
        'semrushbot',
        'petalbot',
        'ahrefsbot',
        'mj12bot',
        'dotbot',
        'applebot',
        'yandexbot',
        'baiduspider',
        'bingbot',
        'slurp'
    ]
    
    return any(bot in user_agent for bot in blocked_bots)

def bot_protection(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_agent = request.headers.get('User-Agent', '')
        ip_address = request.remote_addr
        
        if is_bot(user_agent):
            # Log blocked bot attempt
            logger.warning(f"Blocked bot access - IP: {ip_address}, UA: {user_agent}")
            return jsonify({
                'error': 'Access denied',
                'message': 'This resource is not available to bots or crawlers.'
            }), 403
            
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

def get_device_type():
    """Detect if the user is using Windows"""
    user_agent = request.headers.get('User-Agent', '').lower()
    if 'windows' in user_agent:
        return 'windows'
    return 'unsupported'

def is_ip_blocked(ip_address):
    """Check if an IP is blocked using exact match or pattern matching"""
    blocked_patterns = BlockedIP.query.all()
    for blocked in blocked_patterns:
        if blocked.ip_pattern in ip_address or ip_address in blocked.ip_pattern:
            return True
    return False

def device_protection(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip_address = request.remote_addr
        
        # Check if IP is blocked
        if is_ip_blocked(ip_address):
            logger.warning(f"Blocked IP access attempt: {ip_address}")
            return jsonify({
                'error': 'Access denied',
                'message': 'Your IP address has been blocked.'
            }), 403
            
        device_type = get_device_type()
        if device_type == 'unsupported':
            return jsonify({
                'error': 'Access denied',
                'message': 'This application is only available for Windows PC.'
            }), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@bot_protection
@device_protection
def index():
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    device_type = get_device_type()
    
    # Only track visit and send notification if it's not a recent visit
    if not is_recent_visit(ip_address):
        # Add timestamp for this visit
        visit_timestamps[ip_address].append(datetime.now())
        
        # Track visit in database
        new_visit = Visit(is_mobile=False, ip_address=ip_address)
        db.session.add(new_visit)
        db.session.commit()

        # Get country for the notification
        country = get_country_from_ip(ip_address)

        # Send Telegram notification with country
        message = (
            f"🌐 New Visit:\n"
            f"IP: {ip_address}\n"
            f"Country: {country}\n"
            f"Device: Windows\n"
            f"User Agent: {user_agent}"
        )
        send_telegram_message(message)
    
    return render_template('download.html', device_type=device_type)

@app.route('/track-download', methods=['POST'])
@bot_protection
@device_protection
def track_download():
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    country = get_country_from_ip(ip_address)
    
    # Generate unique filename with timestamp for better tracking
    timestamp = datetime.now().strftime('%m%d')
    unique_id = str(uuid.uuid4())[:6]
    unique_filename = f"v1_2_6_{timestamp}_{unique_id}.win"
    
    new_download = Download(ip_address=ip_address)
    db.session.add(new_download)
    db.session.commit()

    if not WINDOWS_DOWNLOAD_URL:
        return jsonify({
            'success': False,
            'message': 'Download URL is not configured.'
        }), 500

    # Send Telegram notification with country
    message = (
        f"⬇️ New Download:\n"
        f"IP: {ip_address}\n"
        f"Country: {country}\n"
        f"Device: Windows\n"
        f"File: {unique_filename}\n"
        f"User Agent: {user_agent}"
    )
    send_telegram_message(message)
    
    return jsonify({
        'success': True, 
        'download_url': WINDOWS_DOWNLOAD_URL,
        'filename': unique_filename
    })

@app.route('/admin/login', methods=['GET', 'POST'])
@bot_protection
@device_protection
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
    # Get blocked IPs
    blocked_ips = BlockedIP.query.order_by(BlockedIP.timestamp.desc()).all()
    
    # Basic statistics
    total_visits = Visit.query.count()
    total_downloads = Download.query.count()
    conversion_rate = (total_downloads / total_visits * 100) if total_visits > 0 else 0
    
    # Time-based statistics
    now = datetime.utcnow()
    today = now.date()
    this_month = today.replace(day=1)
    
    visits_today = Visit.query.filter(Visit.timestamp >= today).count()
    downloads_today = Download.query.filter(Download.timestamp >= today).count()
    visits_this_month = Visit.query.filter(Visit.timestamp >= this_month).count()
    downloads_this_month = Download.query.filter(Download.timestamp >= this_month).count()
    
    # Country statistics
    country_visits = {}
    country_downloads = {}
    
    for visit in Visit.query.all():
        country = get_country_from_ip(visit.ip_address)
        country_visits[country] = country_visits.get(country, 0) + 1
        
    for download in Download.query.all():
        country = get_country_from_ip(download.ip_address)
        country_downloads[country] = country_downloads.get(country, 0) + 1
    
    # Sort countries by visits
    top_countries = sorted(country_visits.items(), key=lambda x: x[1], reverse=True)[:10]
    
    # Recent activity
    recent_activities = []
    recent_visits = Visit.query.order_by(Visit.timestamp.desc()).limit(10).all()
    recent_downloads = Download.query.order_by(Download.timestamp.desc()).limit(10).all()
    
    for visit in recent_visits:
        country = get_country_from_ip(visit.ip_address)
        recent_activities.append({
            'type': 'Visit',
            'timestamp': visit.timestamp,
            'country': country,
            'ip': visit.ip_address
        })
    
    for download in recent_downloads:
        country = get_country_from_ip(download.ip_address)
        recent_activities.append({
            'type': 'Download',
            'timestamp': download.timestamp,
            'country': country,
            'ip': download.ip_address
        })
    
    recent_activities.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Hourly statistics for today
    hourly_stats = {
        'visits': [0] * 24,
        'downloads': [0] * 24
    }
    
    today_visits = Visit.query.filter(Visit.timestamp >= today).all()
    today_downloads = Download.query.filter(Download.timestamp >= today).all()
    
    for visit in today_visits:
        hour = visit.timestamp.hour
        hourly_stats['visits'][hour] += 1
        
    for download in today_downloads:
        hour = download.timestamp.hour
        hourly_stats['downloads'][hour] += 1
    
    return render_template('admin_dashboard.html',
                         total_visits=total_visits,
                         total_downloads=total_downloads,
                         visits_today=visits_today,
                         downloads_today=downloads_today,
                         visits_this_month=visits_this_month,
                         downloads_this_month=downloads_this_month,
                         conversion_rate=round(conversion_rate, 1),
                         top_countries=top_countries,
                         recent_activities=recent_activities[:10],
                         hourly_stats=hourly_stats,
                         blocked_ips=blocked_ips)

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('admin_login'))

@app.route('/admin/block-ip', methods=['POST'])
@login_required
def block_ip():
    ip_pattern = request.form.get('ip_pattern')
    reason = request.form.get('reason', 'No reason provided')
    
    if not ip_pattern:
        flash('IP pattern is required')
        return redirect(url_for('admin_dashboard'))
        
    try:
        blocked_ip = BlockedIP(ip_pattern=ip_pattern, reason=reason)
        db.session.add(blocked_ip)
        db.session.commit()
        flash(f'Successfully blocked IP pattern: {ip_pattern}')
    except Exception as e:
        flash(f'Error blocking IP: {str(e)}')
        
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/unblock-ip/<int:id>', methods=['POST'])
@login_required
def unblock_ip(id):
    blocked_ip = BlockedIP.query.get_or_404(id)
    try:
        db.session.delete(blocked_ip)
        db.session.commit()
        flash(f'Successfully unblocked IP pattern: {blocked_ip.ip_pattern}')
    except Exception as e:
        flash(f'Error unblocking IP: {str(e)}')
        
    return redirect(url_for('admin_dashboard'))

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
