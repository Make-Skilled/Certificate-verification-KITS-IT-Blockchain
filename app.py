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
    return render_template("user-homepage.html")

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
            return redirect(url_for('organization_dashboard'))  # Redirect to organization dashboard
        else:
            return redirect(url_for('user_dashboard'))  # Redirect to user homepage

    except Exception as e:
        print(f"Error during login: {e}")
        return render_template('login.html', message="An internal error occurred"), 500

@app.route("/organization_dashboard")
def organization_dashboard():
    return render_template("organization-dashboard.html")

@app.route("/user_dashboard")
def user_dashboard():
    return render_template("user-homepage.html")

@app.route('/upload_certificate', methods=['POST'])
def upload_certificate():
    try:
        print(session['user']['address'])
        print(session['user']['usertype'])
        
        user_address = request.form['userAddress']
        file = request.files['imageFile']
        title=request.form['certificateTitle']

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
        contract, web3 = connect_with_blockchain(session['user']['address'])
        if not contract or not web3:
            raise Exception("Failed to connect to blockchain.")

        # Interact with the blockchain to store certificate details
        try:
            print(file_path)
            tx_hash = contract.functions.addCertificate(session['user']['address'],user_address,file_hash,title,file_path).transact()
            web3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"Transaction successful: {tx_hash.hex()}")
        except Exception as blockchain_error:
            print(f"Blockchain interaction error: {blockchain_error}")
            return render_template('upload-certificate.html', message="certificate already exists"), 500

        # Return success message
        return render_template('upload-certificate.html',
                               message='Certificate uploaded and recorded successfully'), 200
    except Exception as e:
        print(f"Error during upload: {e}")
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

@app.route("/logout")
def logout():
    session.clear()
    return render_template('index.html')

@app.route("/manage_certificates")
def manage_certificates():
    return render_template("manage-certificates.html")

@app.route("/list_certificates")
def list_certificates():
    # Validate Ethereum address format
    address=session['user']['address']
    contract, web3 = connect_with_blockchain(address)
    if not contract or not web3:
        raise Exception("Failed to connect to blockchain.")
    
    certificates=contract.functions.getOrganizationCertificates(address).call()
    print(certificates)
    return render_template("list-certificates.html",certificates=certificates)

@app.route("/user_certificates")
def user_certificates():
    # Validate Ethereum address format
    address=session['user']['address']
    contract, web3 = connect_with_blockchain(address)
    if not contract or not web3:
        raise Exception("Failed to connect to blockchain.")
    
    certificates=contract.functions.getUserCertificates(address).call()
    print(certificates)
    return render_template("user_certificates.html",certificates=certificates)

@app.route("/organization_requests")
def organization_requests():
    address=session['user']['address']
    contract, web3 = connect_with_blockchain(address)
    if not contract or not web3:
        raise Exception("Failed to connect to blockchain.")
    
    requests=contract.functions.getOrganizationVerificationCertificates(address).call()
    return render_template("user_requests.html",requests_data=requests)

@app.route("/send_request")
def send_request():
    return render_template("send_request.html")

@app.route("/send_request", methods=["POST"])
def send_orgrequest():
    try:
        user_address=session['user']['address']
        sender_address = request.form['senderAddress']
        issuer_address=request.form['issuerAddress']
        file = request.files['imageFile']

        # Validate the file
        if file.filename == '':
            return render_template('send_request.html', message='No selected file'), 400

        # Secure the filename and save the file to the uploads folder
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Reset the file pointer to the beginning and save the file
        file.seek(0)
        file.save(file_path)

        # Connect to blockchain
        contract, web3 = connect_with_blockchain(session['user']['address'])
        if not contract or not web3:
            raise Exception("Failed to connect to blockchain.")

        # Interact with the blockchain to store certificate details
        try:
            username=contract.functions.getUsername(issuer_address).call()
        except:
            return render_template("send_request.html",message="Sender or the Organization does not exist")
        try:
            tx_hash = contract.functions.addVerificationCertificate(issuer_address,user_address,sender_address,session['user']['username'],username,file_path).transact()
            web3.eth.wait_for_transaction_receipt(tx_hash)
            print(f"Transaction successful: {tx_hash.hex()}")
        except Exception as blockchain_error:
            print(f"Blockchain interaction error: {blockchain_error}")
            return render_template('send_request.html', message=blockchain_error), 500

        # Return success message
        return render_template('send_request.html', message='Certificate uploaded and recorded successfully'), 200
    except Exception as e:
        print(f"Error during upload: {e}")
        return jsonify({'error': f'An error occurred: {str(e)}'}), 500


@app.route('/verify_certificate/<address>')
def verify(address):
    print("address")
    print(address)
    session['organization_address']=address
    return render_template('verify_doc.html')

# Route to handle file upload and hash generation
@app.route('/verify_certificate', methods=['POST'])
def verify_certificate():
    print(session['organization_address'])
    if 'file' not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    if file and file.filename.endswith('.pdf'):
        # Read the file content
        file_content = file.read()
        
        # Generate the hash (using SHA256 in this example)
        file_hash = hashlib.sha256(file_content).hexdigest()

        # Return the hash as a response
        contract, web3 = connect_with_blockchain(session['user']['address'])
        if not contract or not web3:
            raise Exception("Failed to connect to blockchain.")
        
        try:
            response=contract.functions.checkHashExists(session['organization_address'],file_hash).call()
            if(response == "Certificate hash exists"):
                return render_template("verify_doc.html",message="This certificate is authorized and verified")
            else:
                return render_template("verify_doc.html",message="This certificate is not authorized ")
        except Exception as e:
            return render_template('verify_doc.html',message=e)

    return jsonify({"error": "Invalid file type. Only PDF files are allowed."}), 400

@app.route('/accept')
def accept_certificate():
    try:
        # Get the certificate ID and organization address from the request
        certificate_id = request.args.get('id')  # Ensure this is a string passed as query param
        org_address = session['user']['address']

        # Log the addresses and certificate ID for debugging
        print(f"Organization Address: {org_address}")
        print(f"Certificate ID: {certificate_id}")

        # Validate if both the user address and certificate ID are provided
        if not org_address or not certificate_id:
            return jsonify({"error": "Missing user address or certificate ID"}), 400
        
        # Ensure the certificate_id is cast to the correct type
        certificate_id = int(certificate_id)  # Convert to integer

        # Connect to the blockchain and retrieve contract
        contract, web3 = connect_with_blockchain(session['user']['address'])
        
        if not contract or not web3:
            raise Exception("Failed to connect to blockchain.")
        
        # Log the contract object for debugging
        print(f"Contract: {contract}")
        
        # Send the transaction to update the certificate status
        tx_hash = contract.functions.updateCertificateStatus(certificate_id, "Verified").transact()
        
        # Wait for the transaction receipt to ensure it has been mined
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        
        # Log receipt information for debugging
        print(f"Transaction Receipt: {receipt}")
        
        # After success, render the template and pass the success message
        return redirect("/organization_requests")
    
    except Exception as e:
        # Log the error and return it in the response
        print(f"Error: {str(e)}")
        # Render the template with the error message
        return render_template("user_requests.html", error=str(e))
   
@app.route('/org_accept')
def org_accept_certificate():
    try:
        # Get the certificate ID and organization address from the request
        certificate_id = request.args.get('id')  # Ensure this is a string passed as query param
        org_address = session['user']['address']

        # Log the addresses and certificate ID for debugging
        print(f"Organization Address: {org_address}")
        print(f"Certificate ID: {certificate_id}")

        # Validate if both the user address and certificate ID are provided
        if not org_address or not certificate_id:
            return jsonify({"error": "Missing user address or certificate ID"}), 400
        
        # Ensure the certificate_id is cast to the correct type
        certificate_id = int(certificate_id)  # Convert to integer

        # Connect to the blockchain and retrieve contract
        contract, web3 = connect_with_blockchain(session['user']['address'])
        
        if not contract or not web3:
            raise Exception("Failed to connect to blockchain.")
        
        # Log the contract object for debugging
        print(f"Contract: {contract}")
        
        # Send the transaction to update the certificate status
        tx_hash = contract.functions.updateCertificateStatus( certificate_id, "Verified").transact()
        
        # Wait for the transaction receipt to ensure it has been mined
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        
        # Log receipt information for debugging
        print(f"Transaction Receipt: {receipt}")
        
        # After success, render the template and pass the success message
        return redirect("/org_requests")
    
    except Exception as e:
        # Log the error and return it in the response
        print(f"Error: {str(e)}")
        # Render the template with the error message
        return render_template("user_requests.html", error=str(e))
  
@app.route('/reject')
def org_reject_certificate():
    try:
        # Get the certificate ID and organization address from the request
        certificate_id = request.args.get('id')  # Ensure this is a string passed as query param
        org_address = session['user']['address']

        # Log the addresses and certificate ID for debugging
        print(f"Organization Address: {org_address}")
        print(f"Certificate ID: {certificate_id}")

        # Validate if both the user address and certificate ID are provided
        if not org_address or not certificate_id:
            return jsonify({"error": "Missing user address or certificate ID"}), 400
        
        # Ensure the certificate_id is cast to the correct type
        certificate_id = int(certificate_id)  # Convert to integer

        # Connect to the blockchain and retrieve contract
        contract, web3 = connect_with_blockchain(session['user']['address'])
        
        if not contract or not web3:
            raise Exception("Failed to connect to blockchain.")
        
        # Log the contract object for debugging
        print(f"Contract: {contract}")
        
        # Send the transaction to update the certificate status
        tx_hash = contract.functions.updateCertificateStatus( certificate_id, "Rejected").transact()
        
        # Wait for the transaction receipt to ensure it has been mined
        receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
        
        # Log receipt information for debugging
        print(f"Transaction Receipt: {receipt}")
        
        # After success, render the template and pass the success message
        return redirect("/org_requests")
    
    except Exception as e:
        # Log the error and return it in the response
        print(f"Error: {str(e)}")
        # Render the template with the error message
        return render_template("user_requests.html", error=str(e))
  

@app.route('/request_organization', methods=['POST'])
def request_organization():
    # Capture form data
    id = request.form.get('id')
    
    # Connect to the blockchain and retrieve contract
    contract, web3 = connect_with_blockchain(session['user']['address'])
        
    if not contract or not web3:
        raise Exception("Failed to connect to blockchain.")
    
    try:
        tx_hash=contract.functions.changeRequestSentStatus(int(id), True).transact()
        web3.eth.wait_for_transaction_receipt(tx_hash)
        return redirect("/organization_requests")
    except Exception as e:
        return str(e)

@app.route("/org_requests")
def track_certificate():
    contract, web3 = connect_with_blockchain(session['user']['address']) 
    if not contract or not web3:
        raise Exception("Failed to connect to blockchain.")
    
    try:
        requests=contract.functions.getAllRequestSentTrue().call()
        print(requests)
        return render_template("organization_requests.html",requests_data=requests)
    except Exception as e:
        return str(e)
    
@app.route("/feedback")
def feedback():
    return render_template("feedback-form.html")
    
@app.route("/submit-feedback")
def submit_feedback():
    feedback=request.form.get("feedback")
    service=request.form.get("service")
    email=session['user']['email']
    address=session['user']['address']
    
    contract, web3 = connect_with_blockchain(session['user']['address']) 
    if not contract or not web3:
        raise Exception("Failed to connect to blockchain.")
    
    try:
        tx_hash=contract.funtions.addFeedback(address,feedback,service,email).transact()
        web3.eth.wait_for_transaction_receipt(tx_hash)
        return render_template("feedback-form.html",message="Feedback submitted successfully")
    except:
        return render_template("feedback-form.html",message="Failed adding feedback")
    
@app.route("/feedbacks")
def feedbacks():
    contract, web3 = connect_with_blockchain(session['user']['address']) 
    if not contract or not web3:
        raise Exception("Failed to connect to blockchain.")
    try:
        feedbacks=contract.functions.getAllFeedbacks().call()
        return render_template("feedbacks.html",feedbacks=feedbacks)
    except:
        return render_template("feesbacks.html",message="Failed retriving feedbacks")
        
      
if __name__ == '__main__':
    app.run(debug=True, port=9001)
