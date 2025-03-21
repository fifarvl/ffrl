import logging
from app import db, Admin, os, app

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def init_database():
    try:
        with app.app_context():
            logger.info("Dropping all existing tables...")
            db.drop_all()
            
            logger.info("Creating new tables...")
            db.create_all()
            
            # Create admin user if not exists
            admin_username = os.getenv('ADMIN_USERNAME', 'admin')
            admin_password = os.getenv('ADMIN_PASSWORD', 'fifa2024')
            
            logger.info(f"Creating admin user: {admin_username}")
            admin = Admin(username=admin_username, password=admin_password)
            db.session.add(admin)
            db.session.commit()
            
            logger.info("Database initialization completed successfully!")
            return True
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        return False

if __name__ == "__main__":
    init_database() 
