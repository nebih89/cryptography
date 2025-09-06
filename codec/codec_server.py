
#!/usr/bin/env python3
"""
Standalone Temporal Codec Server
Provides encryption/decryption services for Temporal Web UI and CLI
"""

import asyncio
import logging
import os
import base64
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
from temporalio.api.common.v1 import Payload
from google.protobuf.json_format import MessageToDict
from codec.encryption_codec import EncryptionCodec

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create Flask app for codec server
app = Flask(__name__)

# Enable CORS for Temporal Web UI access
CORS(app, resources={
    r"/codec/*": {"origins": "*"},
    r"/health/*": {"origins": "*"}
}, supports_credentials=False)

# Initialize encryption codec
codec = EncryptionCodec()


def convert_ui_payload_to_protobuf(payload_dict: dict) -> Payload:
    """
    Convert Temporal Web UI payload format to protobuf Payload.
    
    Args:
        payload_dict: Dictionary from Temporal Web UI
        
    Returns:
        Temporal protobuf Payload object
    """
    payload = Payload()

    # Handle metadata: map<string, bytes>
    metadata = payload_dict.get("metadata", {})
    for key, value in metadata.items():
        key_bytes = key.encode() if isinstance(key, str) else key
        
        if isinstance(value, str):
            # Try base64 decode first, fallback to UTF-8 encoding
            try:
                payload.metadata[key_bytes] = base64.b64decode(value)
            except Exception:
                payload.metadata[key_bytes] = value.encode('utf-8')
        elif isinstance(value, (bytes, bytearray)):
            payload.metadata[key_bytes] = bytes(value)
        else:
            # Handle other types by converting to string first
            payload.metadata[key_bytes] = str(value).encode('utf-8')

    # Handle data: bytes (usually base64 encoded by UI)
    data = payload_dict.get("data", "")
    if isinstance(data, str) and data:
        try:
            payload.data = base64.b64decode(data)
        except Exception:
            payload.data = data.encode('utf-8')
    elif isinstance(data, (bytes, bytearray)):
        payload.data = bytes(data)
    else:
        payload.data = b""

    return payload

def safe_message_to_dict(payload):
    """
    Safely convert protobuf message to dict, handling different protobuf versions
    """
    try:
        # Try with preserving_proto_field_name only
        return MessageToDict(payload, preserving_proto_field_name=True)
    except Exception as e:
        logger.warning(f"MessageToDict failed with preserving_proto_field_name: {e}")
        try:
            # Try without any parameters
            return MessageToDict(payload)
        except Exception as e2:
            logger.error(f"MessageToDict failed completely: {e2}")
            # Fallback: create a basic dict representation
            return {
                "metadata": {k.decode() if isinstance(k, bytes) else str(k): 
                           base64.b64encode(v).decode() if isinstance(v, bytes) else str(v) 
                           for k, v in payload.metadata.items()},
                "data": base64.b64encode(payload.data).decode() if payload.data else ""
            }

@app.route("/codec/decode", methods=["POST"])
def decode_payloads():
    """
    Decode encrypted payloads for Temporal Web UI.
    
    Expected request format:
    {
        "payloads": [
            {
                "metadata": {...},
                "data": "base64-encoded-data"
            }
        ]
    }
    """
    
    try:
        # Parse request body
        request_body = request.get_json(force=True)
        if not request_body:
            return jsonify({"error": "Empty request body"}), 400
        
        payloads_list = request_body.get("payloads", [])
        if not payloads_list:
            return jsonify({"error": "No payloads provided"}), 400
        
        logger.debug(f"Received {len(payloads_list)} payloads for decoding")
        
        # Convert UI format to protobuf format
        protobuf_payloads = []
        for i, payload_dict in enumerate(payloads_list):
            if not isinstance(payload_dict, dict):
                logger.error(f"Payload {i} is not a dictionary")
                return jsonify({"error": f"Payload {i} must be a dictionary"}), 400
            protobuf_payloads.append(convert_ui_payload_to_protobuf(payload_dict))
        
        # Decode using encryption codec
        decoded_payloads = asyncio.run(codec.decode(protobuf_payloads))
        
        # Convert back to JSON format for UI using safe function
        result_payloads = [safe_message_to_dict(payload) for payload in decoded_payloads]
        
        logger.info(f"Successfully decoded {len(result_payloads)} payloads")
        return jsonify({"payloads": result_payloads})
        
    except Exception as e:
        logger.error(f"Decode operation failed: {e}", exc_info=True)
        return jsonify({
            "error": "Decode operation failed",
            "message": str(e)
        }), 500

@app.route("/codec/encode", methods=["POST"])
def encode_payloads():
    """
    Encode payloads for Temporal Web UI.
    
    Expected request format:
    {
        "payloads": [
            {
                "metadata": {...},
                "data": "base64-encoded-data"
            }
        ]
    }
    """
    
    try:
        # Parse request body
        request_body = request.get_json(force=True)
        if not request_body:
            return jsonify({"error": "Empty request body"}), 400
        
        payloads_list = request_body.get("payloads", [])
        if not payloads_list:
            return jsonify({"error": "No payloads provided"}), 400
        
        logger.debug(f"Received {len(payloads_list)} payloads for encoding")
        
        # Convert UI format to protobuf format
        protobuf_payloads = []
        for i, payload_dict in enumerate(payloads_list):
            if not isinstance(payload_dict, dict):
                logger.error(f"Payload {i} is not a dictionary")
                return jsonify({"error": f"Payload {i} must be a dictionary"}), 400
            protobuf_payloads.append(convert_ui_payload_to_protobuf(payload_dict))
        
        # Encode using encryption codec
        encoded_payloads = asyncio.run(codec.encode(protobuf_payloads))
        
        # Convert back to JSON format for UI using safe function
        result_payloads = [safe_message_to_dict(payload) for payload in encoded_payloads]
        
        logger.info(f"Successfully encoded {len(result_payloads)} payloads")
        return jsonify({"payloads": result_payloads})
        
    except Exception as e:
        logger.error(f"Encode operation failed: {e}", exc_info=True)
        return jsonify({
            "error": "Encode operation failed",
            "message": str(e)
        }), 500

    # Utility endpoint: encode input to base64
@app.route("/to_base64", methods=["POST"])
def to_base64():
    """
    Accepts raw string or JSON {"data": ...} and returns base64-encoded string.
    """
    try:
        if request.is_json:
            body = request.get_json(force=True)
            data = body.get("data", "")
        else:
            data = request.data.decode("utf-8")
        if not data:
            return jsonify({"error": "No data provided"}), 400
        encoded = base64.b64encode(data.encode("utf-8")).decode("ascii")
        return jsonify({"base64": encoded})
    except Exception as e:
        logger.error(f"/to_base64 error: {e}", exc_info=True)
        return jsonify({"error": "base64_encode_failed", "message": str(e)}), 500

# Utility endpoint: decode base64 to plain text
@app.route("/to_json", methods=["POST"])
def to_json():
    """
    Accepts JSON {"value": ...} or raw base64 string and returns decoded plain text.
    """
    try:
        if request.is_json:
            body = request.get_json(force=True)
            b64_value = body.get("value", "")
        else:
            b64_value = request.data.decode("utf-8")
        if not b64_value:
            return jsonify({"error": "No value provided"}), 400
        try:
            decoded_bytes = base64.b64decode(b64_value)
            decoded_text = decoded_bytes.decode("utf-8")
        except Exception as e:
            return jsonify({"error": f"Base64 decode error: {str(e)}"}), 400
        # Try to parse as JSON
        try:
            parsed = json.loads(decoded_text)
            return jsonify(parsed)
        except Exception:
            return jsonify({"plain_text": decoded_text})
    except Exception as e:
        logger.error(f"/from_base64 error: {e}", exc_info=True)
        return jsonify({"error": "base64_decode_failed", "message": str(e)}), 500
    
# Handle accidental double "/decode" in URL
@app.route("/codec/decode/decode", methods=["POST"])
def decode_payloads_alias():
    """Alias endpoint to handle accidental double /decode path"""
    return decode_payloads()

@app.route("/health", methods=["GET"])
@app.route("/health/codec", methods=["GET"])
def health_check():
    """
    Health check endpoint for monitoring and load balancer checks.
    """
    encryption_key = os.getenv('TEMPORAL_ENCRYPTION_KEY')
    
    health_status = {
        "status": "healthy",
        "service": "temporal-codec-server",
        "version": "1.0.0",
        "codec_type": "encryption",
        "encryption_key_configured": bool(encryption_key),
    }
    # Add encryption key length for debugging (without exposing the key)
    if encryption_key:
        health_status["encryption_key_length"] = len(encryption_key)
    return jsonify(health_status), 200

@app.route("/", methods=["GET"])
def root():
    """Root endpoint with basic service information"""
    return jsonify({
        "service": "Temporal Codec Server",
        "version": "1.0.0",
        "endpoints": [
            "/codec/decode",
            "/codec/encode", 
            "/health",
            "/health/codec"
        ],
        "description": "Provides encryption/decryption services for Temporal Web UI"
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        "error": "Endpoint not found",
        "available_endpoints": [
            "/codec/decode",
            "/codec/encode",
            "/to_base64",
            "/to_json",
            "/health",
            "/health/codec"
        ]
    }), 404

@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 errors"""
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(500)
def internal_server_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {error}", exc_info=True)
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    # Configuration from environment variables
    port = int(os.getenv("CODEC_SERVER_PORT", "6000"))
    host = os.getenv("CODEC_SERVER_HOST", "0.0.0.0")
    debug = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    
    # Validate required environment variables
    encryption_key = os.getenv('TEMPORAL_ENCRYPTION_KEY')
    if not encryption_key:
        logger.error("❌ TEMPORAL_ENCRYPTION_KEY environment variable is required!")
        logger.error("   Set this to the same encryption key used by your Temporal workers")
        exit(1)
    
    # Startup logging
    logger.info("=" * 60)
    logger.info("🚀 Starting Temporal Codec Server")
    logger.info("=" * 60)
    logger.info(f"📡 Host: {host}")
    logger.info(f"🔌 Port: {port}")
    logger.info(f"🔧 Debug mode: {debug}")
    logger.info(f"🔑 Encryption key: {'✅ Configured' if encryption_key else '❌ Missing'}")
    
    # No IP allowlist; network security handled externally
    
    logger.info("=" * 60)
    logger.info("📋 Available endpoints:")
    logger.info("   POST /codec/decode  - Decrypt payloads for Temporal UI")
    logger.info("   POST /codec/encode  - Encrypt payloads for Temporal UI") 
    logger.info("   GET  /health        - Health check")
    logger.info("=" * 60)
    
    # Start the Flask application
    app.run(
        debug=debug,
        port=port,
        host=host,
        threaded=True
    )