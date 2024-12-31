from flask import Flask, render_template, request, jsonify, session
from werkzeug.utils import secure_filename
from web3 import Web3, HTTPProvider
import bcrypt
import hashlib
import json
import os

# Blockchain connection function
def connect_with_blockchain(addr):
    try:
        web3 = Web3(HTTPProvider('http://127.0.0.1:7545'))
        if not web3.isConnected():
            raise Exception("Failed to connect to the Ethereum network.")
        
        # Load contract ABI and address
        with open('./build/contracts/certi.json') as f:
            artifact_json = json.load(f)
            contract_abi = artifact_json['abi']
            contract_address = artifact_json['networks']['5777']['address']

        web3.eth.defaultAccount=addr
        contract = web3.eth.contract(abi=contract_abi, address=contract_address)
        return contract, web3
    except Exception as e:
        print(f"Error connecting to blockchain: {e}")
        return None, None

# Flask app setup
app = Flask(__name__)
app.secret_key = 'certificate'\
    
# Configuration
STATIC_FOLDER = 'static'
UPLOAD_FOLDER = os.path.join(STATIC_FOLDER, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the uploads directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/upload_certificate')
def uploadcerti():
    return render_template('upload-certificate.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/register', methods=['POST'])
def register_user():
    try:
        
        # Parse form data
        full_name = request.form.get('fullName')
        email = request.form.get('email').lower()
        password = request.form.get('password')
        username = request.form.get('username')
        address = request.form.get('address')  # Retrieve Ethereum address from the form

        contract, web3 = connect_with_blockchain(address)
        if not contract or not web3:
            raise Exception("Failed to connect to blockchain.")
        
        # Input validation
        if not address or not full_name or not email or not password or not username:
            return render_template('signup.html', error="All fields are required"), 400

        # Validate Ethereum address format
        if not web3.isAddress(address):
            return render_template('signup.html', error="Invalid Ethereum address"), 400

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Interact with the blockchain to add the user
        try:
            tx_hash = contract.functions.addUser(full_name, email, hashed_password, username).transact()
            web3.eth.wait_for_transaction_receipt(tx_hash)
        except Exception as blockchain_error:
            print(f"Blockchain error during registration: {blockchain_error}")
            return render_template('signup.html', error="Email or username already exists"), 500

        # If successful, return a success message
        return render_template('signup.html', message="User registration successful"), 201

    except Exception as e:
        print(f"Error during registration: {e}")
        return render_template('signup.html', error="An internal error occurred"), 500

@app.route('/login', methods=['POST'])
def login_user():
    try:
        # Parse form data
        email = request.form['email']
        password = request.form['password']
        user_address = request.form['address']  # Ethereum address provided by the user
        print(email,password,user_address)
        # Input validation
        if not email or not password or not user_address:
            return render_template('login.html', message="All fields are required")

        contract, web3 = connect_with_blockchain(user_address)
        if not contract or not web3:
            raise Exception("Failed to connect to blockchain.")
        
        fullname,email,username,password=contract.functions.getUser(user_address).call()
        
        # Successful login
        session['user'] = {
            'full_name': fullname,
            'email': email,
            'username': username,
            'address':user_address
        }
        return render_template('user-homepage.html'), 200

    except Exception as e:
        print(f"Error during login: {e}")
        return render_template('login.html', message="An internal error occurred"), 500

@app.route('/upload_certificate', methods=['POST'])
def upload_image():
    try:
        # Check if the 'imageFile' field is in the request
        if 'imageFile' not in request.files:
            return render_template('upload-certificate.html', message='No file part in the request'), 400

        file = request.files['imageFile']

        # Generate hash for the file content
        file_content = file.read()
        file_hash = hashlib.sha256(file_content).hexdigest()
        print(f"File hash: {file_hash}")

        # Check if the file has a name
        if file.filename == '':
            return render_template('upload-certificate.html', message='No selected file'), 400

        # Secure the filename and save the file to the uploads folder inside static
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        

        # Save the file to the specified location
        file.seek(0)  # Reset the file pointer to save the file after reading its content
        file.save(file_path)
        
        user_address=session['user']['address']
        
        contract, web3 = connect_with_blockchain(user_address)
        if not contract or not web3:
            raise Exception("Failed to connect to blockchain.")

        # Interact with the blockchain to store certificate details
        try:
            tx_hash = contract.functions.addCertificate(file_hash, file_path).transact()
            web3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"Transaction successful: {tx_hash.hex()}")
        except Exception as blockchain_error:
            print(f"Blockchain interaction error: {blockchain_error}")
            return render_template('upload-certificate.html', message="Failed to record certificate on blockchain"), 500

        # Return the file path for confirmation
        return render_template('upload-certificate.html',
                               message='Certificate uploaded and recorded successfully'), 200

    except Exception as e:
        print(f"Error during upload: {e}")
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500
  
if __name__ == '__main__':
    app.run(debug=True, port=9001)
