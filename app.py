from flask import Flask, request, send_file, render_template, redirect, url_for, after_this_request
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import hashlib

# --- Configuration ---
app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
DOWNLOAD_FOLDER = 'downloads'

# Create the necessary directories
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

# --- Key Management (Hardcoded for this example) ---
# NOTE: In a production system, this key must be managed securely and not hardcoded.
SECRET_KEY = b'a-very-secret-key-of-32-bytes-for-aes256'
KEY = hashlib.sha256(SECRET_KEY).digest()

# --- Encryption and Decryption Functions ---
def encrypt_file(file_path):
    """Encrypts a file using AES-256 in CBC mode."""
    # Generate a random 16-byte Initialization Vector (IV)
    iv = get_random_bytes(AES.block_size)
    
    # Create the AES cipher object
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    
    # Read the file content
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    # Pad the plaintext to be a multiple of the block size
    padded_data = pad(plaintext, AES.block_size)
    
    # Encrypt the data
    ciphertext = cipher.encrypt(padded_data)
    
    # Create the encrypted file path
    encrypted_file_path = os.path.join(ENCRYPTED_FOLDER, os.path.basename(file_path) + '.enc')
    
    # Write the IV and the ciphertext to the new file
    with open(encrypted_file_path, 'wb') as f:
        f.write(iv + ciphertext)
    
    return encrypted_file_path

def decrypt_file(encrypted_file_path):
    """Decrypts a file using AES-256 in CBC mode."""
    with open(encrypted_file_path, 'rb') as f:
        # Read the 16-byte IV from the beginning of the file
        iv = f.read(AES.block_size)
        # Read the rest of the file as ciphertext
        ciphertext = f.read()
    
    # Create the AES cipher object with the key and IV
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    
    # Decrypt the data and unpad it
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    # Create the decrypted file path
    decrypted_file_path = os.path.join(DOWNLOAD_FOLDER, os.path.basename(encrypted_file_path).replace('.enc', ''))
    
    # Write the decrypted data to the new file
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)
        
    return decrypted_file_path

# --- Flask Routes ---
@app.route('/')
def index():
    """Renders the main page with a list of encrypted files."""
    files = os.listdir(ENCRYPTED_FOLDER)
    return render_template('index.html', files=files)

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handles file uploads, encrypts the file, and deletes the original."""
    if 'file' not in request.files:
        return 'No file part'
    file = request.files['file']
    if file.filename == '':
        return 'No selected file'
    
    # Save the original file temporarily
    upload_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(upload_path)
    
    # Encrypt the file
    encrypted_path = encrypt_file(upload_path)
    
    # Delete the original unencrypted file
    os.remove(upload_path)
    
    return redirect(url_for('index'))

@app.route('/download/<filename>')
def download_file(filename):
    """Handles file downloads by decrypting the file and deleting the temporary version after the download is complete."""
    encrypted_path = os.path.join(ENCRYPTED_FOLDER, filename)
    
    if not os.path.exists(encrypted_path):
        return 'File not found'
    
    decrypted_path = decrypt_file(encrypted_path)

    @after_this_request
    def remove_file(response):
        try:
            os.remove(decrypted_path)
        except Exception as error:
            app.logger.error("Error removing or closing downloaded file: %s", error)
        return response
    
    return send_file(decrypted_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)