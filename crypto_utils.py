from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64
import json

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
