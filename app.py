from flask import Flask, render_template, request, jsonify, session
import bcrypt
from web3 import Web3, HTTPProvider
import json

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
app.secret_key = 'certificate'

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login')
def login():
    return render_template('login.html')

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
            return render_template('signup.html', error="Blockchain interaction failed"), 500

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
            'username': username
        }
        return render_template('user-homepage.html'), 200

    except Exception as e:
        print(f"Error during login: {e}")
        return render_template('login.html', message="An internal error occurred"), 500


if __name__ == '__main__':
    app.run(debug=True, port=9001)
