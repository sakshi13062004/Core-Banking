#!/usr/bin/env python3
"""
Script to create .env file for the banking application
Run this script to create the .env file with proper configuration
"""

import os
from pathlib import Path

# Get the directory where this script is located
BASE_DIR = Path(__file__).resolve().parent

env_content = """# Django Settings
SECRET_KEY=django-insecure-banking-app-secret-key-change-in-production
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database Configuration
DB_NAME=banking_db
DB_USER=postgres
DB_PASSWORD=123
DB_HOST=localhost
DB_PORT=5432

# Redis Configuration (Optional - fallback to file-based cache if not available)
REDIS_URL=redis://localhost:6379/1

# Celery Configuration (Optional)
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# Banking Security (Auto-generated if not provided)
ENCRYPTION_KEY=your-32-byte-encryption-key-here!!
"""

def main():
    env_file = BASE_DIR / '.env'
    
    if env_file.exists():
        print("⚠️  .env file already exists!")
        response = input("Do you want to overwrite it? (y/N): ")
        if response.lower() != 'y':
            print("Cancelled.")
            return
    
    try:
        with open(env_file, 'w') as f:
            f.write(env_content)
        print(f"✅ Created .env file at: {env_file}")
        print("\n📝 Next steps:")
        print("1. Update the database password if needed")
        print("2. Run: python manage.py makemigrations")
        print("3. Run: python manage.py migrate")
        print("4. Run: python manage.py createsuperuser")
        print("5. Run: python manage.py runserver")
    except Exception as e:
        print(f"❌ Error creating .env file: {e}")

if __name__ == '__main__':
    main()
