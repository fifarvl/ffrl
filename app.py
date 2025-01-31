from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import os
from urllib.parse import urlparse
import asyncio
from telegram import Bot
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Telegram Configuration
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID')

# Initialize Telegram bot
bot = Bot(token=TELEGRAM_BOT_TOKEN) if TELEGRAM_BOT_TOKEN else None

async def send_telegram_message(message):
    """Send message to Telegram channel"""
    if bot and TELEGRAM_CHAT_ID:
        try:
            await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message, parse_mode='HTML')
        except Exception as e:
            logger.error(f"Failed to send Telegram message: {e}")

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

# Routes
@app.route('/')
def index():
    # Track visit
    is_mobile = 'Mobile' in request.headers.get('User-Agent', '')
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    new_visit = Visit(is_mobile=is_mobile, ip_address=ip_address)
    db.session.add(new_visit)
    db.session.commit()

    # Send Telegram notification
    message = (
        f"🌐 New Visit:\n"
        f"IP: {ip_address}\n"
        f"Device: {'📱 Mobile' if is_mobile else '💻 Desktop'}\n"
        f"User Agent: {user_agent}"
    )
    asyncio.run(send_telegram_message(message))
    
    return render_template('download.html')

@app.route('/track-download', methods=['POST'])
def track_download():
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    new_download = Download(ip_address=ip_address)
    db.session.add(new_download)
    db.session.commit()

    # Send Telegram notification
    message = (
        f"⬇️ New Download:\n"
        f"IP: {ip_address}\n"
        f"User Agent: {user_agent}"
    )
    asyncio.run(send_telegram_message(message))
    
    return jsonify({'success': True, 'download_url': DOWNLOAD_URL})

@app.route('/admin/login', methods=['GET', 'POST'])
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