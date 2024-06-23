# from flask import Flask, request, jsonify
# import json
# import requests
# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes
# from Crypto.Util.Padding import pad, unpad
# import hashlib

# app = Flask(__name__)


# def encrypt_data(data, key):
#     cipher = AES.new(key, AES.MODE_CBC)
#     encrypted_data = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
#     return cipher.iv + encrypted_data

# def decrypt_data(encrypted_data, key):
#     iv = encrypted_data[:AES.block_size]
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     decrypted_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
#     return decrypted_data.decode('utf-8')

# def calculate_hash(data):
#     return hashlib.sha256(data).hexdigest()

# def write_to_thingspeak(encrypted_data, data_hash, api_key):
#     url = "https://api.thingspeak.com/update.json"
#     data = {
#         "api_key": api_key,
#         "field6": encrypted_data.hex(),
#         "field7": data_hash
#     }
#     response = requests.post(url, data=data)
#     print("ThingSpeak Write Response:", response.text)
#     return response.status_code == 200

# def read_from_thingspeak(api_key, channel_id, field_number):
#     url = f"https://api.thingspeak.com/channels/{channel_id}/fields/{field_number}/last.json"
#     params = {
#         "api_key": api_key
#     }
#     response = requests.get(url, params=params)
#     if response.status_code == 200:
#         data = response.json()
#         return data[f"field{field_number}"]
#     else:
#         print(f"Failed to read field {field_number} from ThingSpeak.")
#         return None


# encryption_key = get_random_bytes(32)  # For demonstration purposes, generate a random key

# @app.route('/encrypt', methods=['POST'])
# def encrypt_and_send():
#     try:
#         # Decode and preprocess the incoming data
#         raw_data = request.data.decode('utf-8')
        
#         # Manually convert the data to valid JSON
#         # Remove the surrounding quotes and convert single quotes to double quotes
#         if raw_data.startswith("'") and raw_data.endswith("'"):
#             raw_data = raw_data[1:-1].replace("'", '"')
        
#         # Add double quotes around the keys
#         json_str = '{' + ','.join(f'"{key.strip()}":{value.strip()}' for key, value in (item.split(':') for item in raw_data.strip('{}').split(','))) + '}'
        
#         # Parse the preprocessed string as JSON
#         sensor_data = json.loads(json_str)
        
#         if not sensor_data:
#             return jsonify({"message": "Invalid JSON data."}), 400
        
#         data_json = json.dumps(sensor_data)
#         encrypted_data = encrypt_data(data_json, encryption_key)
#         data_hash = calculate_hash(encrypted_data)
#         write_api_key = "SEUBKKLNI8GQ8OMR"
        
#         if write_to_thingspeak(encrypted_data, data_hash, write_api_key):
#             return jsonify({"message": "Data written to ThingSpeak successfully."})
#         else:
#             return jsonify({"message": "Failed to write data to ThingSpeak."}), 500
#     except Exception as e:
#         return jsonify({"message": f"An error occurred: {str(e)}"}), 500

# @app.route('/decrypt', methods=['GET'])
# def retrieve_and_decrypt():
#     read_api_key = "SEUBKKLNI8GQ8OMR"
#     channel_id = "2342156"
#     encrypted_data_hex = read_from_thingspeak(read_api_key, channel_id, 6)
#     data_hash = read_from_thingspeak(read_api_key, channel_id, 7)

#     if encrypted_data_hex and data_hash:
#         # Filter out non-hexadecimal characters
#         filtered_hex = ''.join(c for c in encrypted_data_hex if c in '0123456789abcdefABCDEF')
#         print(f"Filtered hex: {filtered_hex}")

#         try:
#             encrypted_data = bytes.fromhex(filtered_hex)
#         except ValueError as e:
#             print(f"Error converting hex to bytes: {e}")
#             return jsonify({"message": "Invalid hexadecimal data."}), 400

#         if calculate_hash(encrypted_data) == data_hash:
#             try:
#                 decrypted_data = decrypt_data(encrypted_data, encryption_key)
#                 loaded_sensor_data = json.loads(decrypted_data)
#                 return jsonify({"sensor_data": loaded_sensor_data})
#             except Exception as e:
#                 print(f"Error decrypting data: {e}")
#                 return jsonify({"message": "Decryption failed."}), 500
#         else:
#             return jsonify({"message": "Data integrity verification failed."}), 400
#     else:
#         return jsonify({"message": "Failed to read data from ThingSpeak."}), 500

# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5000)
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
    return response.status_code == 200

def read_from_thingspeak(api_key, channel_id, field_number):
    url = f"https://api.thingspeak.com/channels/{channel_id}/fields/{field_number}/last.txt"
    params = {"api_key": api_key}
    response = requests.get(url, params=params)
    if response.status_code == 200:
        return response.text.strip()
    return None

encryption_key = get_random_bytes(32)

@app.route('/encrypt', methods=['POST'])
def encrypt_and_send():
    try:
        sensor_data = request.get_json()
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
            encrypted_data = bytes.fromhex(encrypted_data_hex)
            if calculate_hash(encrypted_data) == data_hash:
                decrypted_data = decrypt_data(encrypted_data, encryption_key)
                loaded_sensor_data = json.loads(decrypted_data)
                return jsonify({"sensor_data": loaded_sensor_data})
            else:
                logging.error("Data integrity verification failed.")
                return jsonify({"message": "Data integrity verification failed."}), 400
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
    # Run the Flask application
    app.run(host='0.0.0.0', port=5000)
