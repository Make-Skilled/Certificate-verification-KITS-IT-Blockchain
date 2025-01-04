from flask import Flask, render_template, request, jsonify, session,redirect,url_for
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
app.secret_key = 'certificate'
    
# Configuration
STATIC_FOLDER = 'static'
UPLOAD_FOLDER = os.path.join(STATIC_FOLDER, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'jpg', 'jpeg', 'png', 'gif'}  # Allowed file types

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


# Ensure the uploads directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/admin-login')
def adminlogin():
    return render_template('admin-login.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/upload_certificate')
def uploadcerti():
    return render_template('upload-certificate.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route("/user_homepage")
def user_home():
    return render_template("user-homapage.html")

@app.route("/organization_dashboard")
def org_dash():
    return render_template("organization-dashboard.html")

@app.route('/register', methods=['POST'])
def register_user():
    try:
        # Parse form data
        full_name = request.form.get('fullName')
        email = request.form.get('email').lower()
        password = request.form.get('password')
        username = request.form.get('username')
        address = request.form.get('address')  # Retrieve Ethereum address from the form
        usertype = request.form.get('usertype')

        # Input validation
        if not address or not full_name or not email or not password or not username or not usertype:
            return render_template('signup.html', error="All fields are required"), 400

        if usertype not in ['user', 'organization']:
            return render_template('signup.html', error="Invalid user type"), 400

        # Validate Ethereum address format
        contract, web3 = connect_with_blockchain(address)
        if not contract or not web3:
            raise Exception("Failed to connect to blockchain.")

        if not web3.isAddress(address):
            return render_template('signup.html', error="Invalid Ethereum address"), 400

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Interact with the blockchain to add the user
        try:
            tx_hash = contract.functions.addUser(full_name, email, hashed_password, username, usertype).transact()
            web3.eth.wait_for_transaction_receipt(tx_hash)
        except Exception as blockchain_error:
            print(f"Blockchain error during registration: {blockchain_error}")
            return render_template('signup.html', error="Email or username already exists"), 500

        # If successful, return a success message
        return render_template('signup.html', message="User registration successful"), 201

    except Exception as e:
        print(f"Error during registration: {e}")
        return render_template('signup.html', error="An internal error occurred"), 500

@app.route('/organization_signup')
def org_signup():
    return render_template('organization_signup.html')

@app.route('/organization_login')
def organization_login():
    return render_template('organization_login.html')


@app.route('/login', methods=['POST'])
def login_user():
    try:
        # Parse form data
        email = request.form['email']
        password = request.form['password']
        user_address = request.form['address']  # Ethereum address provided by the user
        usertype = request.form['usertype']  # User type selected by the user (user/organization)
        print(email, password, user_address, usertype)
        
        # Input validation
        if not email or not password or not user_address or not usertype:
            return render_template('login.html', message="All fields are required")

        # Connect to the blockchain contract
        contract, web3 = connect_with_blockchain(user_address)
        if not contract or not web3:
            raise Exception("Failed to connect to blockchain.")

        # Fetch user details from the blockchain (including usertype)
        fullname, email_from_contract, username, stored_password, stored_usertype = contract.functions.getUser(user_address).call()

        # Check if the email from the form matches the one from the blockchain
        if email.lower() != email_from_contract.lower():
            return render_template('login.html', message="Email does not match.")

        # Verify the password (compare hashed passwords)
        if not bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
            return render_template('login.html', message="Incorrect password.")

        # Verify the user type
        if usertype != stored_usertype:
            return render_template('login.html', message="User type does not match.")

        # Successful login - Store session data
        session['user'] = {
            'full_name': fullname,
            'email': email_from_contract,
            'username': username,
            'address': user_address,
            'usertype': stored_usertype
        }

        # Redirect based on usertype
        if stored_usertype == "organization":
            return redirect(url_for('render_organization_dashboard'))  # Redirect to organization dashboard
        else:
            return redirect(url_for('render_user_homepage'))  # Redirect to user homepage

    except Exception as e:
        print(f"Error during login: {e}")
        return render_template('login.html', message="An internal error occurred"), 500
@app.route('/upload_certificate', methods=['POST'])
def upload_certificate():
    try:
        # Validate that all required fields are present
        if 'certificateId' not in request.form or not request.form['certificateId']:
            return render_template('upload-certificate.html', message='Certificate ID is required'), 400
        
        if 'userAddress' not in request.form or not request.form['userAddress']:
            return render_template('upload-certificate.html', message='User Address is required'), 400

        if 'imageFile' not in request.files:
            return render_template('upload-certificate.html', message='No file part in the request'), 400

        # Extract the fields
        certificate_id = request.form['certificateId']
        user_address = request.form['userAddress']
        file = request.files['imageFile']

        # Validate the file
        if file.filename == '':
            return render_template('upload-certificate.html', message='No selected file'), 400

        # Generate hash for the file content
        file_content = file.read()
        file_hash = hashlib.sha256(file_content).hexdigest()
        print(f"File hash: {file_hash}")

        # Secure the filename and save the file to the uploads folder
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Reset the file pointer to the beginning and save the file
        file.seek(0)
        file.save(file_path)

        # Connect to blockchain
        contract, web3 = connect_with_blockchain(user_address)
        if not contract or not web3:
            raise Exception("Failed to connect to blockchain.")

        # Interact with the blockchain to store certificate details
        try:
            print(file_path)
            tx_hash = contract.functions.addCertificate(
                certificate_id, file_hash,file_path, user_address
            ).transact({'from': user_address})
            web3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"Transaction successful: {tx_hash.hex()}")
        except Exception as blockchain_error:
            print(f"Blockchain interaction error: {blockchain_error}")
            return render_template('upload-certificate.html', message="Failed to record certificate on blockchain"), 500

        # Return success message
        return render_template('upload-certificate.html',
                               message='Certificate uploaded and recorded successfully'), 200

    except Exception as e:
        print(f"Error during upload: {e}")
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500
 
@app.route('/get_all_certificates', methods=['GET'])
def get_all_certificates():
    try:
        user_address=session['user']['address']
        # Connect to the blockchain
        contract, web3 = connect_with_blockchain(user_address)
        if not contract or not web3:
            raise Exception("Failed to connect to blockchain.")

        # Call the smart contract to fetch all certificates
        try:
            certificates = contract.functions.getAllCertificates().call()
        except Exception as blockchain_error:
            print(f"Blockchain interaction error: {blockchain_error}")
            return jsonify({'error': 'Failed to fetch all certificates from blockchain'}), 500

        # Format the response
        certificate_list = []
        for cert in certificates:
            certificate_list.append({
                'owner': cert[0],
                'hash': cert[1],
                'filePath': cert[2]
            })

        # Return the certificate data
        return jsonify({'certificates': certificate_list}), 200

    except Exception as e:
        print(f"Error fetching all certificates: {e}")
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@app.route('/get_user_certificates', methods=['GET'])
def get_user_certificates():
    try:
        # Check if the user is logged in
        if 'user' not in session:
            return jsonify({'error': 'User not logged in'}), 401

        # Get the Ethereum address from the session
        user_address = session['user']['address']

        # Connect to the blockchain and the smart contract
        contract, web3 = connect_with_blockchain(user_address)
        if not contract or not web3:
            raise Exception("Failed to connect to blockchain.")

        # Validate Ethereum address format
        if not web3.isAddress(user_address):
            return jsonify({'error': 'Invalid Ethereum address in session'}), 400

        # Call the smart contract function to fetch certificates by owner
        try:
            certificates = contract.functions.getCertificatesByOwner(user_address).call()
        except Exception as blockchain_error:
            print(f"Blockchain interaction error: {blockchain_error}")
            return render_template('certificates.html', error='Failed to fetch certificates from blockchain'), 500

        # Format the response
        certificate_list = []
        for cert in certificates:
            certificate_list.append({
                'owner': cert[0],
                'hash': cert[1],
                'filePath': cert[2]
            })

        # Return the certificates as JSON
        return render_template('certificates.html', certificates=certificate_list), 200

    except Exception as e:
        print(f"Error fetching user certificates: {e}")
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@app.route('/delete_certificate', methods=['GET'])
def delete_certificate():
    try:
        # Check if the user is logged in
        if 'user' not in session:
            return jsonify({'error': 'User not logged in'}), 401

        # Retrieve user address from session
        user_address = session['user']['address']
        # Retrieve the certificate hash from query parameters
        cert_hash = request.args.get('hash')

        if not cert_hash:
            return jsonify({'error': 'Certificate hash is required'}), 400

        # Connect to the blockchain and smart contract
        contract, web3 = connect_with_blockchain(user_address)
        if not contract or not web3:
            return jsonify({'error': 'Failed to connect to blockchain'}), 500

        # Validate the Ethereum address
        if not web3.isAddress(user_address):
            return jsonify({'error': 'Invalid Ethereum address in session'}), 400

        # Interact with the smart contract to delete the certificate
        try:
            tx_hash = contract.functions.deleteCertificate(cert_hash).transact({'from': user_address})
            web3.eth.wait_for_transaction_receipt(tx_hash)
            # Redirect back to the user's certificate page
            return redirect('/get_user_certificates')
        except Exception as blockchain_error:
            print(f"Blockchain interaction error: {blockchain_error}")
            return jsonify({'error': 'Failed to delete certificate from blockchain'}), 500

    except Exception as e:
        print(f"Error in delete_certificate: {e}")
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

# Route to handle certificate upload
@app.route('/upload_pdf', methods=['POST'])
def upload_pdf():
    try:
        # Check if the 'imageFile' field is in the request
        if 'file' not in request.files:
            return render_template('upload-certificate.html', message='No file part in the request'), 400

        file = request.files['file']

        # Check if the file has a name
        if file.filename == '':
            return render_template('upload-certificate.html', message='No selected file'), 400

        # Ensure the file has a valid extension (PDF, image files, etc.)
        if not allowed_file(file.filename):
            return render_template('upload-certificate.html', message='Invalid file type. Allowed types are: PDF, JPG, JPEG, PNG, GIF'), 400

        # Generate hash for the file content
        file_content = file.read()
        file_hash = hashlib.sha256(file_content).hexdigest()
        print(f"File hash: {file_hash}")

        user_address = session['user']['address']
        
        # Connect to the blockchain and smart contract
        contract, web3 = connect_with_blockchain(user_address)
        if not contract or not web3:
            return jsonify({'error': 'Failed to connect to blockchain'}), 500

        # Fetch stored certificates (hashes) from the blockchain
        stored_hashes = contract.functions.getAllCertificateHashes().call()
        
        print(stored_hashes)

        # Get the user address from session (make sure user is logged in)
        if 'user' not in session:
            return render_template('upload-certificate.html', message='User not logged in'), 401
        
        if file_hash in stored_hashes:
            return render_template('verify_doc.html', message='This document is authorized and verified.'), 400
        
        # Return the success message
        return render_template('verify_doc.html', message="This document is unauthorized"), 200

    except Exception as e:
        print(f"Error during upload: {e}")
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500

@app.route('/verify')
def verify():
    return render_template('verify_doc.html')

@app.route("/logout")
def logout():
    session.clear()
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True, port=9001)
