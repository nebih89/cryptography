#!/usr/bin/env python3
"""
Direct test of EncryptionCodec to isolate the issue
"""

import os
import asyncio
from temporalio.api.common.v1 import Payload

# Check environment first
print("🔍 Environment Check:")
print(f"TEMPORAL_ENCRYPTION_KEY set: {bool(os.getenv('TEMPORAL_ENCRYPTION_KEY'))}")
if os.getenv('TEMPORAL_ENCRYPTION_KEY'):
    print(f"Key length: {len(os.getenv('TEMPORAL_ENCRYPTION_KEY'))}")
    print(f"Key starts with: {os.getenv('TEMPORAL_ENCRYPTION_KEY')[:10]}...")

print("\n🧪 Testing EncryptionCodec import...")
try:
    from encryption_codec import EncryptionCodec
    print("✅ EncryptionCodec imported successfully")
except Exception as e:
    print(f"❌ Import failed: {e}")
    exit(1)

print("\n🔧 Testing EncryptionCodec initialization...")
try:
    codec = EncryptionCodec()
    print("✅ EncryptionCodec initialized successfully")
except Exception as e:
    print(f"❌ Initialization failed: {e}")
    print(f"Error type: {type(e).__name__}")
    import traceback
    traceback.print_exc()
    exit(1)

print("\n📦 Creating test payload...")
try:
    test_payload = Payload()
    test_payload.data = b"Hello World Test"
    test_payload.metadata[b"test"] = b"value"
    print("✅ Test payload created")
except Exception as e:
    print(f"❌ Payload creation failed: {e}")
    exit(1)

print("\n🔐 Testing encode...")
try:
    encoded = asyncio.run(codec.encode([test_payload]))
    print("✅ Encode successful")
    print(f"Encoded payload data length: {len(encoded[0].data)}")
except Exception as e:
    print(f"❌ Encode failed: {e}")
    print(f"Error type: {type(e).__name__}")
    import traceback
    traceback.print_exc()
    exit(1)

print("\n🔓 Testing decode...")
try:
    decoded = asyncio.run(codec.decode(encoded))
    print("✅ Decode successful")
    print(f"Decoded data: {decoded[0].data}")
    print(f"Original matches decoded: {decoded[0].data == test_payload.data}")
except Exception as e:
    print(f"❌ Decode failed: {e}")
    print(f"Error type: {type(e).__name__}")
    import traceback
    traceback.print_exc()
    exit(1)

print("\n🎉 All tests passed! EncryptionCodec is working correctly.")