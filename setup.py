#!/usr/bin/env python3
"""
Core Banking API Setup Script

This script automates the setup process for the Core Banking API system.
It handles database creation, migrations, initial data loading, and more.
"""

import os
import sys
import subprocess
import django
from pathlib import Path

# Add the project directory to Python path
BASE_DIR = Path(__file__).resolve().parent
sys.path.append(str(BASE_DIR))

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_banking.settings')
django.setup()

from django.core.management import execute_from_command_line
from django.contrib.auth import get_user_model
from demo_app.models import UserRole, Account
from decimal import Decimal

User = get_user_model()


def run_command(command, description=""):
    """Run a command and handle errors"""
    print(f"\n{'='*50}")
    print(f"📍 {description}")
    print(f"{'='*50}")
    
    try:
        if isinstance(command, list):
            result = subprocess.run(command, check=True, capture_output=True, text=True)
        else:
            result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        
        if result.stdout:
            print(result.stdout)
        print(f"✅ {description} completed successfully!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error in {description}:")
        print(f"Error: {e}")
        if e.stderr:
            print(f"Error output: {e.stderr}")
        return False


def create_database():
    """Create PostgreSQL database if it doesn't exist"""
    print("\n🗄️  Setting up database...")
    
    # Check if PostgreSQL is running
    try:
        subprocess.run(['psql', '--version'], check=True, capture_output=True)
        print("✅ PostgreSQL is installed")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ PostgreSQL is not installed or not in PATH")
        print("Please install PostgreSQL and ensure it's in your system PATH")
        return False
    
    # Create database and user
    db_commands = [
        "CREATE DATABASE banking_db;",
        "CREATE USER banking_user WITH PASSWORD 'password';",
        "GRANT ALL PRIVILEGES ON DATABASE banking_db TO banking_user;",
        "ALTER USER banking_user CREATEDB;"
    ]
    
    for cmd in db_commands:
        try:
            subprocess.run([
                'psql', '-h', 'localhost', '-U', 'postgres', 
                '-c', cmd
            ], check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError:
            # Database might already exist, continue
            pass
    
    print("✅ Database setup completed")
    return True


def setup_environment():
    """Setup environment file"""
    env_content = """# Django Settings
SECRET_KEY=django-insecure-banking-app-secret-key-change-in-production
DEBUG=True
ALLOWED_HOSTS=localhost,127.0.0.1

# Database Configuration
DB_NAME=banking_db
DB_USER=banking_user
DB_PASSWORD=password
DB_HOST=localhost
DB_PORT=5432

# Redis Configuration
REDIS_URL=redis://localhost:6379/1

# Celery Configuration
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/0

# Banking Security
ENCRYPTION_KEY=your-32-byte-encryption-key-here!!
"""
    
    env_file = BASE_DIR / '.env'
    if not env_file.exists():
        with open(env_file, 'w') as f:
            f.write(env_content)
        print("✅ Created .env file")
    else:
        print("ℹ️  .env file already exists")
    
    return True


def run_migrations():
    """Run Django migrations"""
    print("\n🔄 Running database migrations...")
    
    # Make migrations
    if not run_command(['python', 'manage.py', 'makemigrations'], "Making migrations"):
        return False
    
    # Apply migrations
    if not run_command(['python', 'manage.py', 'migrate'], "Applying migrations"):
        return False
    
    return True


def create_superuser():
    """Create Django superuser"""
    print("\n👤 Creating superuser...")
    
    if User.objects.filter(is_superuser=True).exists():
        print("ℹ️  Superuser already exists")
        return True
    
    print("Please create a superuser account:")
    try:
        execute_from_command_line(['manage.py', 'createsuperuser'])
        return True
    except KeyboardInterrupt:
        print("\n❌ Superuser creation cancelled")
        return False


def load_initial_data():
    """Load initial data"""
    print("\n📊 Loading initial data...")
    
    # Create user roles
    roles_data = [
        {'name': 'CUSTOMER', 'description': 'Bank Customer'},
        {'name': 'TELLER', 'description': 'Bank Teller'},
        {'name': 'MANAGER', 'description': 'Bank Manager'},
        {'name': 'ADMIN', 'description': 'System Administrator'},
        {'name': 'AUDITOR', 'description': 'System Auditor'},
    ]
    
    for role_data in roles_data:
        role, created = UserRole.objects.get_or_create(
            name=role_data['name'],
            defaults={'description': role_data['description']}
        )
        if created:
            print(f"✅ Created role: {role.name}")
        else:
            print(f"ℹ️  Role already exists: {role.name}")
    
    return True


def create_demo_user():
    """Create demo user with sample account"""
    print("\n🎭 Creating demo user...")
    
    # Create demo user
    demo_user, created = User.objects.get_or_create(
        username='demo_user',
        defaults={
            'email': 'demo@example.com',
            'first_name': 'Demo',
            'last_name': 'User',
            'phone_number': '+1234567890',
            'is_account_verified': True
        }
    )
    
    if created:
        demo_user.set_password('demo123')
        demo_user.save()
        
        # Assign customer role
        customer_role = UserRole.objects.get(name='CUSTOMER')
        demo_user.roles.add(customer_role)
        
        print("✅ Created demo user: demo_user / demo123")
        
        # Create demo account
        demo_account = Account.objects.create(
            account_holder=demo_user,
            account_type='SAVINGS',
            balance=Decimal('1000.00'),
            minimum_balance=Decimal('100.00')
        )
        print(f"✅ Created demo account: {demo_account.account_number}")
    else:
        print("ℹ️  Demo user already exists")
    
    return True


def check_dependencies():
    """Check if all dependencies are installed"""
    print("\n🔍 Checking dependencies...")
    
    dependencies = [
        ('django', 'Django'),
        ('rest_framework', 'Django REST Framework'),
        ('psycopg2', 'PostgreSQL adapter'),
        ('redis', 'Redis client'),
        ('cryptography', 'Cryptography library')
    ]
    
    missing_deps = []
    for dep, name in dependencies:
        try:
            __import__(dep)
            print(f"✅ {name} is installed")
        except ImportError:
            print(f"❌ {name} is missing")
            missing_deps.append(name)
    
    if missing_deps:
        print(f"\n❌ Missing dependencies: {', '.join(missing_deps)}")
        print("Please run: pip install -r requirements.txt")
        return False
    
    return True


def test_redis_connection():
    """Test Redis connection"""
    print("\n🔗 Testing Redis connection...")
    
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=0)
        r.ping()
        print("✅ Redis connection successful")
        return True
    except Exception as e:
        print(f"❌ Redis connection failed: {e}")
        print("Please make sure Redis is running on localhost:6379")
        return False


def main():
    """Main setup function"""
    print("🏦 Core Banking API Setup")
    print("=" * 50)
    
    # Check Python version
    if sys.version_info < (3, 9):
        print("❌ Python 3.9+ is required")
        sys.exit(1)
    
    print(f"✅ Python {sys.version_info.major}.{sys.version_info.minor} detected")
    
    # Setup steps
    steps = [
        (check_dependencies, "Checking dependencies"),
        (setup_environment, "Setting up environment"),
        (create_database, "Creating database"),
        (run_migrations, "Running migrations"),
        (load_initial_data, "Loading initial data"),
        (create_superuser, "Creating superuser"),
        (create_demo_user, "Creating demo user"),
        (test_redis_connection, "Testing Redis connection")
    ]
    
    failed_steps = []
    
    for step_func, step_name in steps:
        try:
            if not step_func():
                failed_steps.append(step_name)
        except Exception as e:
            print(f"❌ Error in {step_name}: {e}")
            failed_steps.append(step_name)
    
    # Summary
    print("\n" + "=" * 50)
    print("📋 SETUP SUMMARY")
    print("=" * 50)
    
    if not failed_steps:
        print("🎉 All setup steps completed successfully!")
        print("\n🚀 Next steps:")
        print("1. Start the development server: python manage.py runserver")
        print("2. Visit http://localhost:8000/ to see the API")
        print("3. Visit http://localhost:8000/admin/ for admin interface")
        print("4. Visit http://localhost:8000/api/docs/swagger/ for API documentation")
        print("\n📝 Demo credentials:")
        print("   Username: demo_user")
        print("   Password: demo123")
    else:
        print(f"❌ {len(failed_steps)} step(s) failed:")
        for step in failed_steps:
            print(f"   - {step}")
        print("\nPlease resolve the issues and run the setup again.")
        sys.exit(1)


if __name__ == '__main__':
    main()
