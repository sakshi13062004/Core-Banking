#!/usr/bin/env python3
"""
Generate a proper Fernet encryption key for the banking application
"""

from cryptography.fernet import Fernet
import base64

def generate_encryption_key():
    """Generate a proper Fernet encryption key"""
    key = Fernet.generate_key()
    print(f"Generated encryption key: {key.decode()}")
    return key

def main():
    print("🔐 Banking Application - Encryption Key Generator")
    print("=" * 50)
    
    key = generate_encryption_key()
    
    print("\n📝 Add this key to your .env file:")
    print(f"ENCRYPTION_KEY={key.decode()}")
    
    print("\n⚠️  IMPORTANT SECURITY NOTES:")
    print("- Keep this key secure and private")
    print("- Don't commit this key to version control")
    print("- Use a different key for production")
    print("- If you lose this key, encrypted data cannot be recovered")

if __name__ == '__main__':
    main()
