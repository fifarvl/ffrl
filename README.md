# FIFA Rivals Download Page

A Flask web application for the FIFA Rivals game download page with analytics tracking.

## Features

- Download page with mobile detection
- Admin dashboard with analytics
- Visit and download tracking
- Mobile vs Desktop statistics
- Conversion rate tracking

## Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd fifa-rivals
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set environment variables:
```bash
# Required environment variables:
export SECRET_KEY=your-secret-key
export DATABASE_URL=your-database-url
export DOWNLOAD_URL=your-game-download-url

# Optional environment variables (defaults shown):
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD=fifa2024
```

5. Initialize the database:
```bash
python
>>> from app import app, init_db
>>> init_db()
>>> exit()
```

6. Run the application:
```bash
python app.py
```

## Deployment on Render

1. Create a new Web Service on Render
2. Connect your GitHub repository
3. Configure the following settings:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn app:app`

### Required Environment Variables on Render

Set the following environment variables in your Render dashboard:

- `SECRET_KEY`: A secure secret key for Flask sessions
- `DATABASE_URL`: This will be automatically set by Render if you create a PostgreSQL database
- `DOWNLOAD_URL`: Your game download URL
- `ADMIN_USERNAME`: Custom admin username (optional)
- `ADMIN_PASSWORD`: Custom admin password (optional)

### Database Setup on Render

1. Create a new PostgreSQL database in your Render dashboard
2. Render will automatically add the `DATABASE_URL` to your web service
3. The application will automatically handle database migrations

### Security Notes

1. Always change the default admin credentials in production
2. Use strong, unique passwords
3. Keep your `SECRET_KEY` secure and unique
4. Never commit sensitive environment variables to version control

## Local Development

For local development, the application will use SQLite by default if no `DATABASE_URL` is provided. The database file will be created in the `database` directory.

## Default Admin Credentials

Default credentials (please change in production):
- Username: admin
- Password: fifa2024

You can change these by setting the `ADMIN_USERNAME` and `ADMIN_PASSWORD` environment variables. 