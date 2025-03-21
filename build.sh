#!/usr/bin/env bash
# exit on error
set -o errexit

# Install Python dependencies
pip install -r requirements.txt

# Create necessary directories if they don't exist
mkdir -p database

# Create empty __init__.py files if needed
touch database/__init__.py

# Initialize database using startup script
python startup.py

# Set proper permissions
chmod -R 755 . 