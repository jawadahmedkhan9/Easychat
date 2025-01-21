from flask import Flask, request, jsonify
import os
import requests
import json
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

class HybridCipher:
    def __init__(self):
        # Generate 2048-bit RSA key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
    def get_public_key_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def set_peer_public_key(self, peer_public_key_bytes):
        self.peer_public_key = serialization.load_pem_public_key(
            peer_public_key_bytes,
            backend=default_backend()
        )
    
    def encrypt(self, data):
        # Generate a random AES key and IV
        aes_key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)       # 128-bit IV
        
        # Encrypt the AES key with RSA
        encrypted_key = self.peer_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Create AES cipher
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Convert data to JSON and pad
        json_data = json.dumps(data).encode('utf-8')
        padded_data = self._pad(json_data)
        
        # Encrypt the actual data with AES
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine all components and encode
        combined = {
            'key': base64.b64encode(encrypted_key).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8'),
            'data': base64.b64encode(encrypted_data).decode('utf-8')
        }
        
        return json.dumps(combined)
    
    def decrypt(self, encrypted_package):
        # Parse the encrypted package
        package = json.loads(encrypted_package)
        encrypted_key = base64.b64decode(package['key'].encode('utf-8'))
        iv = base64.b64decode(package['iv'].encode('utf-8'))
        encrypted_data = base64.b64decode(package['data'].encode('utf-8'))
        
        # Decrypt the AES key with RSA
        aes_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Create AES cipher
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Decrypt and unpad the data
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        json_data = self._unpad(padded_data)
        
        # Convert back to Python object
        return json.loads(json_data)
    
    def _pad(self, data):
        # PKCS7 padding
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad(self, padded_data):
        # PKCS7 unpadding
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]
app = Flask(__name__)
cipher = HybridCipher()

# Configuration
MODEL_SERVICE_PORT = 5001
OLLAMA_ENDPOINT = "http://localhost:11434"

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'}), 200

@app.route('/exchange_keys', methods=['POST'])
def exchange_keys():
    try:
        peer_public_key = request.get_data()
        cipher.set_peer_public_key(peer_public_key)
        return cipher.get_public_key_bytes()
    except Exception as e:
        print(f"[ERROR] Key exchange failed: {str(e)}")
        return jsonify({'error': 'Key exchange failed'}), 500

@app.route('/api/generate', methods=['POST'])
def generate():
    try:
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
            
        encrypted_data = request.json.get('encrypted_data')
        if not encrypted_data:
            return jsonify({'error': 'No encrypted data provided'}), 400
            
        decrypted_data = cipher.decrypt(encrypted_data)
        response = process_generation_request(decrypted_data)
        encrypted_response = cipher.encrypt(response)
        
        return jsonify({'encrypted_response': encrypted_response})
    except Exception as e:
        print(f"[ERROR] Generation request failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/ocr', methods=['POST'])
def ocr():
    try:
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
            
        encrypted_data = request.json.get('encrypted_data')
        if not encrypted_data:
            return jsonify({'error': 'No encrypted data provided'}), 400
            
        decrypted_data = cipher.decrypt(encrypted_data)
        ocr_result = process_ocr_request(decrypted_data)
        encrypted_response = cipher.encrypt({'ocr_result': ocr_result})
        
        return jsonify({'encrypted_response': encrypted_response})
    except Exception as e:
        print(f"[ERROR] OCR request failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

def process_generation_request(data):
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(
            f"{OLLAMA_ENDPOINT}/api/generate",
            headers=headers,
            json=data
        )
        response.raise_for_status()
        
        response_text = response.text.strip()
        lines = response_text.split("\n")
        
        full_response = []
        for line in lines:
            obj = json.loads(line)
            full_response.append(obj.get("response", ""))
            if obj.get("done", False) is True:
                break
        
        return {'response': "".join(full_response).strip()}
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Ollama request failed: {str(e)}")
        raise
    except json.JSONDecodeError as e:
        print(f"[ERROR] JSON parsing failed: {str(e)}")
        raise
    except Exception as e:
        print(f"[ERROR] Unexpected error: {str(e)}")
        raise

def process_ocr_request(data):
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(
            f"{OLLAMA_ENDPOINT}/api/generate",
            headers=headers,
            json=data
        )
        response.raise_for_status()
        
        response_text = response.text.strip()
        lines = response_text.split("\n")
        
        full_response = []
        for line in lines:
            obj = json.loads(line)
            full_response.append(obj.get("response", ""))
            if obj.get("done", False) is True:
                break
        
        return "".join(full_response).strip()
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Ollama request failed: {str(e)}")
        raise
    except json.JSONDecodeError as e:
        print(f"[ERROR] JSON parsing failed: {str(e)}")
        raise
    except Exception as e:
        print(f"[ERROR] Unexpected error: {str(e)}")
        raise

if __name__ == "__main__":
    print(f"Starting Model Service on port {MODEL_SERVICE_PORT}")
    app.run(host='0.0.0.0', port=MODEL_SERVICE_PORT)
