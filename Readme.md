
```markdown
# Flask CloudFront Signed URL Generator

This is a Flask web application that generates signed URLs for Amazon CloudFront, allowing secure access to your CloudFront resources. The signed URL contains a policy, a signature, and a key pair ID to validate the request and ensure that it meets the specified conditions (like expiration time).

## Overview

This Flask application generates signed URLs for CloudFront resources. It uses RSA signing with a private key to create a policy that includes an expiration time. The signed URL allows secure access to CloudFront resources by validating the policy, signature, and key pair ID.

## Requirements

- Python 3.6+
- Flask
- cryptography
- base64
- json

## Installation

1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd <repository_directory>
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. Ensure you have your CloudFront private key file and update the `CLOUDFRONT_KEY_PAIR_ID`, `CLOUDFRONT_URL`, and `PRIVATE_KEY_PATH` in the code.

## Running the Application

To run the application:
```bash
python app.py
```

The application will run on `http://0.0.0.0:8080`.

## API Endpoint

- **Endpoint**: `/generate-signed-url`
- **Method**: GET
- **Parameters**: `object_key` (required)

### Example Request

```
GET /generate-signed-url?object_key=your-object-key
```

### Example Response

```json
{
  "signed_url": "https://d29y3iyouiqp6h.cloudfront.net/your-object-key?Policy=...&Signature=...&Key-Pair-Id=..."
}
```

## Code Breakdown

### Imports

```python
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64
import json
```
- **Flask**: A lightweight WSGI web application framework.
- **datetime and timedelta**: For handling date and time operations.
- **cryptography.hazmat.primitives**: For cryptographic operations like hashing, padding, and serialization.
- **base64**: For encoding binary data to ASCII.
- **json**: For encoding and decoding JSON data.

### Flask App Initialization

```python
app = Flask(__name__)
```
Creates a Flask application instance.

### Constants

```python
CLOUDFRONT_KEY_PAIR_ID = 'K304710OSEWKEE'
CLOUDFRONT_URL = 'https://d29y3iyouiqp6h.cloudfront.net'
PRIVATE_KEY_PATH = 'private_key.pem'
```
- **CLOUDFRONT_KEY_PAIR_ID**: The ID of the CloudFront key pair.
- **CLOUDFRONT_URL**: The base URL of your CloudFront distribution.
- **PRIVATE_KEY_PATH**: The path to your private key file used for signing the URL.

### Loading the Private Key

```python
def load_private_key():
    with open(PRIVATE_KEY_PATH, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
    return private_key
```
This function loads the private key from the specified file using the cryptography library. The private key is used to sign the policy.

### RSA Signer

```python
def rsa_signer(message):
    private_key = load_private_key()
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA1()
    )
    return signature
```
This function signs a message (the policy) with the private key using RSA with PKCS1v15 padding and SHA1 hashing.

### Generating Signed URL

```python
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
```

1. **expires_at**: Calculates the expiration time in UTC.
2. **expires_at_unix**: Converts the expiration time to a Unix timestamp.
3. **policy**: Creates a policy JSON object defining the resource and expiration condition.
4. **policy_json**: Encodes the policy as a JSON string.
5. **policy_b64**: Encodes the JSON string in base64.
6. **signature**: Signs the policy using the `rsa_signer` function.
7. **signature_b64**: Encodes the signature in base64.
8. **signed_url**: Constructs the signed URL with the policy, signature, and key pair ID as query parameters.

### Flask Route

```python
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
```
- **Route**: `/generate-signed-url`
- **Method**: GET
- **Parameters**: `object_key` (passed as a query parameter)
- **Logic**:
  - Retrieves the `object_key` from the request.
  - If `object_key` is missing, returns a 400 error.
  - Generates the signed URL using `generate_signed_url`.
  - Returns the signed URL in the response, or a 500 error if an exception occurs.

### Main Function

```python
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```
- Runs the Flask application on all available IP addresses (`0.0.0.0`) and port `8080`.

## Docker Deployment

### Dockerfile

```dockerfile
# Use the official Python image from the Docker Hub
FROM python:3.9-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Set the working directory
WORKDIR /app

# Copy the requirements file
COPY requirements.txt /app/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . /app/

# Expose the port the app runs on
EXPOSE 8080

# Command to run the application
CMD ["python", "app.py"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  flask_app:
    image: signed_url:v1
    build: .
    ports:
      - "8080:8080"
    restart: unless-stopped
```

This Docker Compose file will build the Docker image and run the Flask application, exposing it on port 8080.
```
