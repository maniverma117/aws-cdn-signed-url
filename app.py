from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64
import json

app = Flask(__name__)

CLOUDFRONT_KEY_PAIR_ID = 'K304710OSSDDSEWKEE'
CLOUDFRONT_URL = 'https://d29y3idfyodfghfuiqp6h.cloudfront.net'
PRIVATE_KEY_PATH = 'private_key.pem'

def load_private_key():
    with open(PRIVATE_KEY_PATH, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
    return private_key

def rsa_signer(message):
    private_key = load_private_key()
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA1()
    )
    return signature

def generate_signed_url(object_key, ttl=19840):
    expires_at = datetime.utcnow() + timedelta(seconds=ttl)
    expires_at_unix = int(expires_at.timestamp())
    
    policy = {
        "Statement": [
            {
                "Resource": f"{CLOUDFRONT_URL}/{object_key}",
                "Condition": {
                    "DateLessThan": {"AWS:EpochTime": expires_at_unix}
                }
            }
        ]
    }
    
    policy_json = json.dumps(policy).encode('utf-8')
    policy_b64 = base64.b64encode(policy_json).decode('utf-8')
    
    signature = rsa_signer(policy_json)
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    
    signed_url = (
        f"{CLOUDFRONT_URL}/{object_key}"
        f"?Policy={policy_b64}"
        f"&Signature={signature_b64}"
        f"&Key-Pair-Id={CLOUDFRONT_KEY_PAIR_ID}"
    )
    
    return signed_url

@app.route('/generate-signed-url', methods=['GET'])
def generate_signed_url_route():
    object_key = request.args.get('object_key')
    if not object_key:
        return jsonify({"error": "Missing required parameter: object_key"}), 400

    try:
        signed_url = generate_signed_url(object_key)
        return jsonify({"signed_url": signed_url}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

