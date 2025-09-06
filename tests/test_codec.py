import requests
import base64

# Prepare a payload dict (simulate Temporal payload)
payload = {
    "metadata": {"encoding": base64.b64encode(b"json/plain").decode()},
    "data": base64.b64encode(b'{"hello":"world"}').decode()
}

# Encode via CODEC webservice
encode_resp = requests.post(
    "http://127.0.0.1:6000/codec/encode",
    json={"payloads": [payload]}
)
encode_resp.raise_for_status()
encoded_payloads = encode_resp.json()["payloads"]

# Decode via CODEC webservice
decode_resp = requests.post(
    "http://127.0.0.1:6000/codec/decode",
    json={"payloads": encoded_payloads}
)
decode_resp.raise_for_status()
decoded_payloads = decode_resp.json()["payloads"]

# Check round-trip
assert decoded_payloads[0]["metadata"]["encoding"] == base64.b64encode(b"json/plain").decode()
assert base64.b64decode(decoded_payloads[0]["data"]) == b'{"hello":"world"}'
print("✅ Codec webservice round-trips")