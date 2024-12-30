from flask import Flask, render_template, request, jsonify
from pymongo import MongoClient
import bcrypt
from web3 import Web3, HTTPProvider
import json

# Blockchain connection function
def connectWithBlockchain():
    try:
        web3 = Web3(HTTPProvider('http://127.0.0.1:7545'))
        web3.eth.default_account = web3.eth.accounts[0]

        # Load contract ABI and address
        with open('./build/contracts/certi.json') as f:  # Ensure the file path is correct
            artifact_json = json.load(f)
            contract_abi = artifact_json['abi']
            contract_address = artifact_json['networks']['5777']['address']

        contract = web3.eth.contract(abi=contract_abi, address=contract_address)
        return contract, web3
    except Exception as e:
        print(f"Error connecting to blockchain: {e}")
        return None, None

# Flask app setup
app = Flask(__name__)
app.secret_key = 'certificate'

# Blockchain connection
contract, web3 = connectWithBlockchain()
if not contract or not web3:
    raise Exception("Failed to connect to blockchain.")

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
        username = request.form.get('username')  # New field for unique username

        # Input validation
        if not full_name or not email or not password or not username:
            return render_template('signup.html',error="All fields are required"),400

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Interact with the blockchain to add the user
        tx_hash = contract.functions.addUser(full_name, email, hashed_password, username).transact()
        web3.eth.wait_for_transaction_receipt(tx_hash)

        return render_template('signup.html',message="User registration successful"), 201

    except Exception as e:
        return jsonify({'error': f"An error occurred: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=9001)
