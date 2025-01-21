from flask import Flask, request, jsonify
from flask_cors import CORS
import pymysql.cursors
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, decode_token
)
from datetime import timedelta, datetime
import re
import numpy as np
import faiss
from sentence_transformers import SentenceTransformer
import spacy
import pickle
import os
import PyPDF2
import pandas as pd
import io
from PIL import Image
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
class ModelService:
    def __init__(self, model_endpoint="http://localhost:5001"):
        self.model_endpoint = model_endpoint
        self.generate_endpoint = f"{model_endpoint}/api/generate"
        self.cipher = HybridCipher()
        self.exchange_keys()
    
    def exchange_keys(self):
        try:
            response = requests.post(
                f"{self.model_endpoint}/exchange_keys",
                data=self.cipher.get_public_key_bytes()
            )
            response.raise_for_status()
            peer_public_key = response.content
            self.cipher.set_peer_public_key(peer_public_key)
            print("[INFO] Key exchange successful")
        except Exception as e:
            print(f"[ERROR] Key exchange failed: {str(e)}")
            raise

    def generate_response(self, system_message, user_message):
        prompt_str = f"{system_message}\n\nUser: {user_message}\nAssistant:"
        data = {
            "model": "llama3.2:1b",
            "prompt": prompt_str,
            "options": {"stream": False}
        }
        
        encrypted_data = self.cipher.encrypt(data)
        headers = {'Content-Type': 'application/json'}
        
        try:
            response = requests.post(
                self.generate_endpoint,
                headers=headers,
                json={'encrypted_data': encrypted_data}
            )
            response.raise_for_status()
            
            encrypted_response = response.json()['encrypted_response']
            decrypted_response = self.cipher.decrypt(encrypted_response)
            
            return decrypted_response['response']
        except Exception as e:
            print(f"[ERROR] Model generation failed: {str(e)}")
            raise

    def perform_ocr(self, image_bytes):
        image_b64 = base64.b64encode(image_bytes).decode('utf-8')
        
        data = {
            "model": "llama3.2:1b",
            "prompt": "OCR analysis request",
            "options": {"stream": False},
            "images": [image_b64]
        }
        
        encrypted_data = self.cipher.encrypt(data)
        headers = {'Content-Type': 'application/json'}
        
        try:
            response = requests.post(
                f"{self.model_endpoint}/ocr",
                headers=headers,
                json={'encrypted_data': encrypted_data}
            )
            response.raise_for_status()
            
            encrypted_response = response.json()['encrypted_response']
            decrypted_response = self.cipher.decrypt(encrypted_response)
            
            return decrypted_response['ocr_result']
        except Exception as e:
            print(f"[ERROR] OCR request failed: {str(e)}")
            return None

# Set Hugging Face to offline mode
os.environ['HF_HUB_OFFLINE'] = '1'

app = Flask(__name__)
CORS(app)

# Initialize model service
model_service = ModelService()

# JWT Configuration
app.config['JWT_SECRET_KEY'] = '479f7dee3a07e66e5844095f020d32106d49915385e1079e'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=1)
jwt = JWTManager(app)

# Configure MySQL connection
connection = pymysql.connect(
    host='localhost',
    port=3306,
    user='root',
    password='Jawadkhan222',
    database='Easychat',
    cursorclass=pymysql.cursors.DictCursor
)

# Store user chat history and OCR data
user_chat_history = {}
greeted_users = set()

# Initialize embedding model and NLP model
embedding_model = SentenceTransformer('models/all-MiniLM-L6-v2', local_files_only=True)
embedding_dimension = embedding_model.get_sentence_embedding_dimension()
nlp = spacy.load('en_core_web_sm')

# Paths to the directories containing your PDF and Excel files
PDF_DIR = '/home/jawad/Documents/PDFeasy'
EXCEL_DIR = '/home/jawad/Documents/Exceleasy'

def load_documents():
    document_texts = []
    document_mappings = {}
    doc_id = 0

    # Process PDF files
    if os.path.exists(PDF_DIR):
        for filename in os.listdir(PDF_DIR):
            if filename.lower().endswith('.pdf'):
                file_path = os.path.join(PDF_DIR, filename)
                with open(file_path, 'rb') as f:
                    reader = PyPDF2.PdfReader(f)
                    num_pages = len(reader.pages)
                    text = ''
                    for page_num in range(num_pages):
                        page = reader.pages[page_num]
                        text += page.extract_text()
                if text.strip():
                    document_texts.append(text)
                    document_mappings[doc_id] = f"Document: {filename}"
                    doc_id += 1
                else:
                    print(f"[DEBUG] Skipping empty document: {filename}")
    else:
        print(f"[WARNING] PDF directory '{PDF_DIR}' does not exist.")

    # Process Excel files
    if os.path.exists(EXCEL_DIR):
        for filename in os.listdir(EXCEL_DIR):
            if filename.lower().endswith(('.xls', '.xlsx', '.xlsm', '.xlsb')):
                file_path = os.path.join(EXCEL_DIR, filename)
                try:
                    df = pd.read_excel(file_path)
                    text = df.to_string()
                    if text.strip():
                        document_texts.append(text)
                        document_mappings[doc_id] = f"Document: {filename}"
                        doc_id += 1
                    else:
                        print(f"[DEBUG] Skipping empty document: {filename}")
                except Exception as e:
                    print(f"[ERROR] Failed to read Excel file '{filename}': {str(e)}")
    else:
        print(f"[WARNING] Excel directory '{EXCEL_DIR}' does not exist.")

    print(f"[DEBUG] Document mappings loaded: {document_mappings}")
    return document_texts, document_mappings

# Load or create FAISS index and document mappings
if os.path.exists('faiss_index.bin') and os.path.exists('doc_mappings.pkl') and os.path.exists('document_texts.pkl'):
    index = faiss.read_index('faiss_index.bin')
    with open('doc_mappings.pkl', 'rb') as f:
        document_mappings = pickle.load(f)
    with open('document_texts.pkl', 'rb') as f:
        document_texts = pickle.load(f)
else:
    document_texts, document_mappings = load_documents()
    if document_texts:
        document_embeddings = embedding_model.encode(document_texts)
        index = faiss.IndexFlatL2(embedding_dimension)
        index.add(np.array(document_embeddings))
        # Save the index and mappings for future use
        faiss.write_index(index, 'faiss_index.bin')
        with open('doc_mappings.pkl', 'wb') as f:
            pickle.dump(document_mappings, f)
        with open('document_texts.pkl', 'wb') as f:
            pickle.dump(document_texts, f)
    else:
        print("[ERROR] No documents found to index.")
        index = None

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    print(f"[DEBUG] Login attempt: email={email}, password={password}")

    with connection.cursor() as cursor:
        query = "SELECT * FROM users WHERE email=%s AND password=%s"
        cursor.execute(query, (email, password))
        user = cursor.fetchone()

    if user:
        print(f"[DEBUG] User found in database: {user}")
        
        if 'current_user_email' in app.config:
            previous_user_email = app.config['current_user_email']
            if previous_user_email in user_chat_history:
                del user_chat_history[previous_user_email]
                print(f"[DEBUG] Cleared previous user chat history for: {previous_user_email}")

        app.config['current_user_email'] = email
        app.config['current_user_data'] = user

        access_token = create_access_token(identity={'email': email})
        refresh_token = create_refresh_token(identity={'email': email})
        token_expiration = datetime.utcnow() + app.config['JWT_ACCESS_TOKEN_EXPIRES']

        print(f"[DEBUG] Access Token generated: {access_token}")
        print(f"[DEBUG] Refresh Token generated: {refresh_token}")
        print(f"[DEBUG] Token Expiration Time: {token_expiration}")

        response = {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'user_data': user
        }
        return jsonify(response)
    else:
        print(f"[DEBUG] Login failed - Invalid email or password: email={email}")
        return jsonify({'message': 'Invalid email or password!'}), 401

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    print(f"[DEBUG] Refresh token used by: {current_user}")
    
    new_access_token = create_access_token(identity=current_user)
    print(f"[DEBUG] New Access Token generated: {new_access_token}")
    
    return jsonify({'access_token': new_access_token}), 200

@app.route('/token-status', methods=['GET'])
@jwt_required()
def token_status():
    token = request.headers.get('Authorization').split()[1]
    decoded_token = decode_token(token)
    exp = decoded_token.get('exp')
    expiration_time = datetime.utcfromtimestamp(exp)
    current_time = datetime.utcnow()
    time_remaining = expiration_time - current_time

    print(f"[DEBUG] Token Expiration Time: {expiration_time}")
    print(f"[DEBUG] Time Remaining: {time_remaining}")

    if time_remaining.total_seconds() <= 0:
        print(f"[DEBUG] Token expired")
        return jsonify({'message': 'Token expired'}), 401

    return jsonify({'time_remaining': str(time_remaining)})

def extract_personal_info_from_ocr(ocr_text):
    # Use regular expressions to extract CNIC and name (if applicable)
    cnic_pattern = r'\d{5}-\d{7}-\d'
    name_pattern = r'نام\s*:\s*(.+)'

    extracted_cnic_match = re.search(cnic_pattern, ocr_text)
    extracted_name_match = re.search(name_pattern, ocr_text)

    extracted_cnic = extracted_cnic_match.group() if extracted_cnic_match else None
    extracted_name = extracted_name_match.group(1).strip() if extracted_name_match else None

    print(f"[DEBUG] Extracted CNIC: {extracted_cnic}")
    print(f"[DEBUG] Extracted Name: {extracted_name}")

    return extracted_cnic, extracted_name

def extract_entities(text):
    doc = nlp(text)
    return [(ent.text, ent.label_) for ent in doc.ents]

@app.route('/query', methods=['POST'])
@jwt_required()
def query():
    try:
        current_user = get_jwt_identity()
        user_email = current_user['email']
        user_data = app.config.get('current_user_data', {})

        print(f"[DEBUG] Current user: {user_email}")

        if user_email not in user_chat_history:
            user_chat_history[user_email] = []
            print(f"[DEBUG] Initialized chat history for: {user_email}")

        ocr_data = None

        if 'image' in request.files:
            print("[DEBUG] Image file received for OCR")
            image_file = request.files['image']

            if image_file.filename == '':
                print("[ERROR] No selected file")
                return jsonify({'error': 'No selected file'}), 400

            image_bytes = image_file.read()
            ocr_data = model_service.perform_ocr(image_bytes)
            print(f"[DEBUG] OCR data extracted: {ocr_data if ocr_data else 'None'}")
        else:
            print("[DEBUG] No image file received for OCR")

        user_input = request.form.get('query', '')
        print(f"[DEBUG] User query received: {user_input}")

        if user_input:
            user_chat_history[user_email].append({'role': 'user', 'content': user_input})
            print("[DEBUG] Appended user query to chat history.")
        else:
            print("[DEBUG] No user query provided.")

        ocr_string = "No OCR data available."
        if ocr_data:
            extracted_cnic, extracted_name = extract_personal_info_from_ocr(ocr_data)

            if extracted_cnic or extracted_name:
                user_cnic = user_data.get('cnic')
                user_name = f"{user_data.get('first_name', '')} {user_data.get('last_name', '')}"

                if extracted_cnic == user_cnic or (extracted_name and extracted_name.lower() == user_name.lower()):
                    ocr_string = f"OCR Data: {ocr_data}"
                    print("[DEBUG] OCR matches user's credentials.")
                else:
                    ocr_string = "OCR data contains personal information that doesn't match your credentials and cannot be disclosed."
                    print("[DEBUG] OCR personal info does not match user's credentials.")
            else:
                ocr_string = f"OCR Data: {ocr_data}"
                print("[DEBUG] OCR does not contain personal info, included in context.")
        else:
            print("[DEBUG] No OCR data available for inclusion.")

        if index is None:
            print("[ERROR] No FAISS index available.")
            retrieved_documents = []
        else:
            user_embedding = embedding_model.encode([user_input])
            k = 3
            distances, indices = index.search(np.array(user_embedding), k)
            retrieved_documents = []
            for idx in indices[0]:
                if idx < len(document_texts):
                    doc_title = document_mappings.get(idx, f"Document at index {idx} (title not found)")
                    doc_content = document_texts[idx]
                    retrieved_documents.append(f"{doc_title}\n{doc_content}")
                    print(f"[DEBUG] Retrieved doc idx {idx}, title: {doc_title}")
                else:
                    print(f"[WARNING] Index {idx} out of range for document_texts")

        entities = extract_entities(user_input)
        print(f"[DEBUG] Extracted entities: {entities}")

        previous_chat = "\n".join([f"{msg['role']}: {msg['content']}" for msg in user_chat_history[user_email]])

        greeting = ""
        if user_email not in greeted_users:
            greeting = f"Hello {user_data.get('first_name', '')}! It's great to chat with you."
            greeted_users.add(user_email)

        prompt_context = "\n\n".join(retrieved_documents[:3])
        print(f"[DEBUG] Prompt context:\n{prompt_context}")

        system_message = "You are EasyChat, a friendly virtual assistant for Easypaisa. Provide clear and concise answers in a conversational tone. Do not mention that you are a chatbot unless directly asked."

        user_message = f"""
{greeting}

User Personal Information ( KYC ):
{user_data}

Uploaded Image Data (if any):
{ocr_string}

This is the user's chat history ( previous chat history with you ):
{previous_chat}

User's Next question:
{user_input}
"""

        print(f"[DEBUG] Full prompt to model:\n{system_message}\n{user_message}")
        response = model_service.generate_response(system_message, user_message)
        print(f"[DEBUG] Model response: {response}")

        user_chat_history[user_email].append({'role': 'assistant', 'content': response})
        return jsonify({'response': response})

    except Exception as e:
        print(f"[DEBUG] Error occurred in query processing: {str(e)}")
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

if __name__ == "__main__":
    app.run(debug=True)
