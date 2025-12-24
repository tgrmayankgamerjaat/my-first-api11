from flask import Flask, request, jsonify
import requests
import hashlib
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64

# --- Configuration ---
SECRET_SEED = "APIMPDS$9712Q"
IV_STR = "AP4123IMPDS@12768F"
API_URL = 'http://impds.nic.in/impdsmobileapi/api/getrationcard'
TOKEN = "91f01a0a96c526d28e4d0c1189e80459"
USER_AGENT = 'Dalvik/2.1.0 (Linux; U; Android 14; 22101320I Build/UKQ1.240624.001)'

# ✅ API Access Key
ACCESS_KEY = "paidchx"

app = Flask(__name__)

# --- Utility Functions ---
def get_md5_hex(input_string: str) -> str:
    return hashlib.md5(input_string.encode('iso-8859-1')).hexdigest()

def generate_session_id() -> str:
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    return "28" + timestamp

def generate_key_material(session_id: str) -> str:
    inner_hash = get_md5_hex(SECRET_SEED)
    combined_string = inner_hash + session_id
    return get_md5_hex(combined_string)

def derive_aes_key(key_material: str) -> bytes:
    sha256 = hashlib.sha256(key_material.encode('utf-8')).digest()
    return sha256[:16]

def encrypt_payload(plaintext_id: str, session_id: str) -> str:
    key_material = generate_key_material(session_id)
    aes_key = derive_aes_key(key_material)
    iv = IV_STR.encode('utf-8')[:16]
    
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    data_bytes = plaintext_id.encode('utf-8')
    padded_data = pad(data_bytes, AES.block_size, style='pkcs7')
    ciphertext = cipher.encrypt(padded_data)
    
    b64_encoded_inner = base64.b64encode(ciphertext)
    b64_double_encoded = base64.b64encode(b64_encoded_inner)
    
    return b64_double_encoded.decode('utf-8')

# --- Flask Route (GET) ---
@app.route('/fetch', methods=['GET'])
def fetch():
    try:
        # ✅ Key Validation
        key = request.args.get("key", "").strip()
        if key != ACCESS_KEY:
            return jsonify({"error": "Invalid API key"}), 401

        aadhaar_input = request.args.get("aadhaar", "").strip()

        if not aadhaar_input or not aadhaar_input.isdigit() or len(aadhaar_input) != 12:
            return jsonify({"error": "Invalid Aadhaar number. Must be 12 digits."}), 400

        session_id = generate_session_id()
        encrypted_id = encrypt_payload(aadhaar_input, session_id)

        headers = {
            'User-Agent': USER_AGENT,
            'Content-Type': 'application/json; charset=utf-8'
        }
        payload = {
            "id": encrypted_id,
            "idType": "U",
            "userName": "IMPDS",
            "token": TOKEN,
            "sessionId": session_id
        }

        response = requests.post(API_URL, headers=headers, json=payload, timeout=15)

        return jsonify(response.json())

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Network error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

# --- Run Server ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

