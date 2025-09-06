#!/usr/bin/env python3
"""
Generate a Fernet encryption key for Temporal codec
"""

from cryptography.fernet import Fernet
import base64

# Generate a new Fernet key
key = Fernet.generate_key()
key_string = key.decode()

print("🔑 Generated Temporal Encryption Key:")
print(f"TEMPORAL_ENCRYPTION_KEY={key_string}")
print()
print("💡 Usage:")
print(f"export TEMPORAL_ENCRYPTION_KEY=\"{key_string}\"")
print()
print("⚠️  IMPORTANT: Use the same key in your Temporal workers!")
print("   This key must be consistent across all services that need to encrypt/decrypt data.")