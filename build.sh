#!/usr/bin/env bash
# exit on error
set -o errexit

# Install Python dependencies
pip install -r requirements.txt

# Create necessary directories
mkdir -p database

# Create empty __init__.py files if needed
touch database/__init__.py

# Run database migrations (if any)
python -c "from app import init_db; init_db()" 