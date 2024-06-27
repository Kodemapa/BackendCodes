import json
import requests
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
from flask import Flask, request, jsonify
from flask_cors import CORS
import logging

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.DEBUG)

def encrypt_data(data, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(data.encode(), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return iv + encrypted_data

def decrypt_data(encrypted_data, key):
    iv = encrypted_data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(encrypted_data[AES.block_size:])
    unpadded_data = unpad(decrypted_data, AES.block_size)
    return unpadded_data.decode()

def calculate_hash(data):
    return hashlib.sha256(data).hexdigest()

def write_to_thingspeak(encrypted_data, data_hash, api_key):
    url = f"https://api.thingspeak.com/update?api_key={api_key}"
    payload = {
        "field1": encrypted_data.hex(),
        "field2": data_hash
    }
    response = requests.post(url, data=payload)
    logging.debug(f"ThingSpeak write response: {response.text}")
    return response.status_code == 200

def read_from_thingspeak(api_key, channel_id, field_number):
    url = f"https://api.thingspeak.com/channels/{channel_id}/fields/{field_number}/last.txt"
    params = {"api_key": api_key}
    response = requests.get(url, params=params)
    logging.debug(f"ThingSpeak read response (field {field_number}): {response.text.strip()}")
    if response.status_code == 200:
        return response.text.strip()
    return None

# Use a static key for demonstration purposes (in a real application, use a secure method to store and retrieve keys)
encryption_key = get_random_bytes(32)

@app.route('/')
def home():
    return "Welcome to the Flask App"

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/encrypt', methods=['POST'])
def encrypt_and_send():
    try:
        sensor_data = request.get_json()
        if not sensor_data:
            logging.error("No JSON data received.")
            return jsonify({"message": "No JSON data received."}), 400
        
        logging.debug(f"Received sensor data: {sensor_data}")
        data_json = json.dumps(sensor_data)
        encrypted_data = encrypt_data(data_json, encryption_key)
        data_hash = calculate_hash(encrypted_data)
        write_api_key = "SEUBKKLNI8GQ8OMR"

        if write_to_thingspeak(encrypted_data, data_hash, write_api_key):
            return jsonify({"message": "Data written to ThingSpeak successfully."})
        else:
            logging.error("Failed to write data to ThingSpeak.")
            return jsonify({"message": "Failed to write data to ThingSpeak."}), 500
    except Exception as e:
        logging.error(f"Error in /encrypt endpoint: {e}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/decrypt', methods=['GET'])
def retrieve_and_decrypt():
    try:
        read_api_key = "SEUBKKLNI8GQ8OMR"
        channel_id = "2342156"
        encrypted_data_hex = read_from_thingspeak(read_api_key, channel_id, 1)
        data_hash = read_from_thingspeak(read_api_key, channel_id, 2)

        if encrypted_data_hex and data_hash:
            try:
                encrypted_data = bytes.fromhex(encrypted_data_hex)
                if calculate_hash(encrypted_data) == data_hash:
                    decrypted_data = decrypt_data(encrypted_data, encryption_key)
                    loaded_sensor_data = json.loads(decrypted_data)
                    return jsonify({"sensor_data": loaded_sensor_data})
                else:
                    logging.error("Data integrity verification failed.")
                    return jsonify({"message": "Data integrity verification failed."}), 400
            except ValueError as e:
                logging.error(f"Error converting hex to bytes: {e}")
                return jsonify({"message": "Invalid hexadecimal data."}), 400
            except Exception as e:
                logging.error(f"Error decrypting data: {e}")
                return jsonify({"message": "Decryption failed."}), 500
        else:
            logging.error("Failed to read data from ThingSpeak.")
            return jsonify({"message": "Failed to read data from ThingSpeak."}), 500
    except Exception as e:
        logging.error(f"Error in /decrypt endpoint: {e}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

@app.route('/integrity-check', methods=['GET'])
def perform_integrity_check():
    try:
        encryption_algorithm = "AES"
        encryption_mode = "CBC"
        key_size = len(encryption_key) * 8
        block_size = AES.block_size * 8
        iv_used = True
        padding_scheme = "PKCS7"
        hashing_algorithm = "SHA-256"

        integrity_check_results = {
            "Encryption Algorithm": encryption_algorithm,
            "Encryption Mode": encryption_mode,
            "Key Size": f"{key_size} bits",
            "Block Size": f"{block_size} bits",
            "Initialization Vector (IV) Used": iv_used,
            "Padding Scheme": padding_scheme,
            "Hashing Algorithm": hashing_algorithm
        }

        return jsonify({"integrity_check_results": integrity_check_results})
    except Exception as e:
        logging.error(f"Error in /integrity-check endpoint: {e}")
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
