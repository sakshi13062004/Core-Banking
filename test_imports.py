#!/usr/bin/env python3
"""
Simple test script to check if Django setup works without errors
"""

import os
import sys
import django
from pathlib import Path

# Add the project directory to Python path
BASE_DIR = Path(__file__).resolve().parent
sys.path.append(str(BASE_DIR))

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core_banking.settings')

def test_django_setup():
    """Test Django setup and imports"""
    try:
        print("🔍 Testing Django setup...")
        django.setup()
        print("✅ Django setup successful!")
        
        print("\n🔍 Testing model imports...")
        from demo_app.models import User, Account, Transaction
        print("✅ Model imports successful!")
        
        print("\n🔍 Testing view imports...")
        from demo_app.views import UserRegistrationView, AccountViewSet
        print("✅ View imports successful!")
        
        print("\n🔍 Testing URL imports...")
        from demo_app.urls import urlpatterns
        print("✅ URL imports successful!")
        
        print("\n🔍 Testing admin imports...")
        from demo_app.admin import CustomUserAdmin
        print("✅ Admin imports successful!")
        
        return True
        
    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("🏦 Banking Application Import Test")
    print("=" * 50)
    
    success = test_django_setup()
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 All imports successful! The application should work now.")
        print("\n📝 Next steps:")
        print("1. Create .env file: python create_env.py")
        print("2. Run migrations: python manage.py makemigrations")
        print("3. Apply migrations: python manage.py migrate")
        print("4. Create superuser: python manage.py createsuperuser")
        print("5. Start server: python manage.py runserver")
    else:
        print("❌ There are still issues to resolve.")
        print("Check the error messages above for details.")

if __name__ == '__main__':
    main()
