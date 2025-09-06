"""
Fixed EncryptionCodec that works with Temporal protobuf Payload objects
"""

import os
from typing import List
from temporalio.api.common.v1 import Payload
from temporalio.converter import PayloadCodec
from cryptography.fernet import Fernet

class EncryptionCodec(PayloadCodec):
    """
    Codec that encrypts/decrypts Temporal protobuf Payload objects
    """
    
    def __init__(self):
        """Initialize with encryption key from environment"""
        key = os.getenv('TEMPORAL_ENCRYPTION_KEY')
        if not key:
            raise ValueError("TEMPORAL_ENCRYPTION_KEY environment variable is required")
        
        print(f"🔑 DEBUG: Key from environment: {bool(key)}")
        print(f"🔑 DEBUG: Key length: {len(key) if key else 0}")
        
        try:
            self.fernet = Fernet(key.encode())
            print("🔑 DEBUG: Fernet initialized successfully")
        except Exception as e:
            raise ValueError(f"Invalid TEMPORAL_ENCRYPTION_KEY format: {e}")
    
    async def encode(self, payloads: List[Payload]) -> List[Payload]:
        """
        Encrypt Temporal protobuf Payload objects
        
        Args:
            payloads: List of Temporal protobuf Payload objects
            
        Returns:
            List of encrypted Temporal protobuf Payload objects
        """
        print(f"🔐 DEBUG: Encoding {len(payloads)} payloads")
        encoded_payloads = []
        
        for i, payload in enumerate(payloads):
            print(f"🔐 DEBUG: Processing payload {i}, type: {type(payload)}")
            
            # Skip empty payloads
            if not payload.data:
                print(f"🔐 DEBUG: Payload {i} has no data, skipping encryption")
                encoded_payloads.append(payload)
                continue
            
            try:
                print(f"🔐 DEBUG: Payload {i} data length: {len(payload.data)}")
                
                # Encrypt the payload data (payload.data is bytes)
                encrypted_data = self.fernet.encrypt(payload.data)
                print(f"🔐 DEBUG: Encrypted data length: {len(encrypted_data)}")
                
                # Create new payload with encrypted data
                encoded_payload = Payload()
                encoded_payload.data = encrypted_data
                
                # Copy all existing metadata
                for key, value in payload.metadata.items():
                    encoded_payload.metadata[key] = value
                
                # Add encryption marker
                encoded_payload.metadata[b"encrypted"] = b"true"
                
                encoded_payloads.append(encoded_payload)
                print(f"🔐 DEBUG: Payload {i} encrypted successfully")
                
            except Exception as e:
                print(f"🔐 DEBUG: Encryption failed for payload {i}: {e}")
                raise RuntimeError(f"Encryption failed for payload {i}: {e}")
        
        print(f"🔐 DEBUG: Successfully encoded {len(encoded_payloads)} payloads")
        return encoded_payloads
    
    async def decode(self, payloads: List[Payload]) -> List[Payload]:
        """
        Decrypt Temporal protobuf Payload objects
        
        Args:
            payloads: List of encrypted Temporal protobuf Payload objects
            
        Returns:
            List of decrypted Temporal protobuf Payload objects
        """
        print(f"🔓 DEBUG: Decoding {len(payloads)} payloads")
        decoded_payloads = []
        
        for i, payload in enumerate(payloads):
            print(f"🔓 DEBUG: Processing payload {i}, type: {type(payload)}")
            
            # Check if payload is encrypted by looking for our marker
            is_encrypted = payload.metadata.get(b"encrypted") == b"true"
            print(f"🔓 DEBUG: Payload {i} encrypted: {is_encrypted}")
            
            if not is_encrypted:
                # Not encrypted, return as-is
                decoded_payloads.append(payload)
                continue
            
            try:
                print(f"🔓 DEBUG: Payload {i} encrypted data length: {len(payload.data)}")
                
                # Decrypt the payload data
                decrypted_data = self.fernet.decrypt(payload.data)
                print(f"🔓 DEBUG: Decrypted data length: {len(decrypted_data)}")
                
                # Create new payload with decrypted data
                decoded_payload = Payload()
                decoded_payload.data = decrypted_data
                
                # Copy metadata (except our encryption marker)
                for key, value in payload.metadata.items():
                    if key != b"encrypted":
                        decoded_payload.metadata[key] = value
                
                decoded_payloads.append(decoded_payload)
                print(f"🔓 DEBUG: Payload {i} decrypted successfully")
                
            except Exception as e:
                print(f"🔓 DEBUG: Decryption failed for payload {i}: {e}")
                raise RuntimeError(f"Decryption failed for payload {i}: {e}")
        
        print(f"🔓 DEBUG: Successfully decoded {len(decoded_payloads)} payloads")
        return decoded_payloads