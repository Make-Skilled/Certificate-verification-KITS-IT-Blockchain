// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract Certi {
    // Struct to represent a user
    struct User {
        string fullName;
        string email;
        string password; // Store hashed password
        string username;
        string usertype; // Add the user type field
    }

    // Struct to represent a certificate
    struct Certificate {
        address issuer;  // Address of the user who issued the certificate
        string hash;     // Hash of the certificate file
        string filePath; // Path of the stored certificate
        string description; // Description of the certificate
    }

    // Mapping to store users by their Ethereum address
    mapping(address => User) private users;

    // Mapping to ensure unique usernames
    mapping(string => bool) private usernames;

    // Mapping to store certificates by their hash
    mapping(string => Certificate) private certificates;

    // Mapping to store certificates associated with a user's address
    mapping(address => Certificate[]) private user_certificates;

    // Mapping from certificateId to Certificate struct for easy lookup by ID
    mapping(string => Certificate) public certificateDetails;

    // Array to store all certificate hashes for global access
    string[] public allCertificateHashes;

    // Function to add a new user
    function addUser(
        string memory fullName, 
        string memory email, 
        string memory password, 
        string memory username, 
        string memory usertype // Add usertype parameter
    ) public {
        require(bytes(fullName).length > 0, "Full name is required.");
        require(bytes(email).length > 0, "Email is required.");
        require(bytes(password).length > 0, "Password is required.");
        require(bytes(username).length > 0, "Username is required.");
        require(bytes(usertype).length > 0, "User type is required.");

        require(bytes(users[msg.sender].email).length == 0, "User already registered.");
        require(!usernames[username], "Username already taken.");

        users[msg.sender] = User(fullName, email, password, username, usertype); // Store usertype
        usernames[username] = true;
    }

    // Function to fetch user details
    function getUser(address userAddress)
        public
        view
        returns (string memory fullName, string memory email, string memory username, string memory password, string memory usertype)
    {
        User memory user = users[userAddress];
        require(bytes(user.email).length > 0, "User not found.");
        return (user.fullName, user.email, user.username, user.password, user.usertype); // Return usertype
    }

    // Function to add a certificate
    function addCertificate(
        string memory certificateId,
        string memory hash,
        string memory filePath,
        string memory description, // New field
        address userAddress,
        address addedBy
    ) public {
        require(bytes(certificateId).length > 0, "Certificate ID is required.");
        require(bytes(hash).length > 0, "Certificate hash is required.");
        require(bytes(filePath).length > 0, "File path is required.");
        require(bytes(description).length > 0, "Description is required."); // Validate description
        require(userAddress != address(0), "User address is required.");
        require(bytes(certificates[hash].hash).length == 0, "Certificate already exists.");
        require(bytes(certificateDetails[certificateId].hash).length == 0, "Certificate ID already exists.");

        // Create a new Certificate struct and add it to the mappings
        certificates[hash] = Certificate(addedBy, hash, filePath, description); // Include description
        certificateDetails[certificateId] = certificates[hash];

        // Map the certificate to the user and store the hash in allCertificateHashes
        user_certificates[userAddress].push(certificates[hash]);
        allCertificateHashes.push(hash);
    }

    // Function to fetch certificates for a specific address
    function getCertificates(address userAddress) public view returns (Certificate[] memory) {
        return user_certificates[userAddress];
    }

    // Function to fetch all certificates in the system
    function getAllCertificates() public view returns (Certificate[] memory) {
        Certificate[] memory allCertificates = new Certificate[](allCertificateHashes.length);

        for (uint256 i = 0; i < allCertificateHashes.length; i++) {
            string memory certificateHash = allCertificateHashes[i];
            allCertificates[i] = certificates[certificateHash];
        }

        return allCertificates;
    }

    // Function to fetch all certificates associated with a specific address
    function getCertificatesByOwner(address userAddress) public view returns (Certificate[] memory) {
        return user_certificates[userAddress];
    }

    // Function to delete a certificate
    function deleteCertificate(string memory hash) public {
        Certificate memory cert = certificates[hash];
        require(bytes(cert.hash).length > 0, "Certificate not found.");
        require(cert.issuer == msg.sender, "Only the issuer can delete the certificate.");

        // Remove from the certificates mapping
        delete certificates[hash];

        // Remove from allCertificateHashes
        for (uint256 i = 0; i < allCertificateHashes.length; i++) {
            if (keccak256(bytes(allCertificateHashes[i])) == keccak256(bytes(hash))) {
                allCertificateHashes[i] = allCertificateHashes[allCertificateHashes.length - 1];
                allCertificateHashes.pop();
                break;
            }
        }

        // Remove from user_certificates
        Certificate[] storage userCerts = user_certificates[msg.sender];
        for (uint256 i = 0; i < userCerts.length; i++) {
            if (keccak256(bytes(userCerts[i].hash)) == keccak256(bytes(hash))) {
                userCerts[i] = userCerts[userCerts.length - 1];
                userCerts.pop();
                break;
            }
        }
    }

    // Function to retrieve all stored certificate hashes across all users
    function getAllCertificateHashes() public view returns (string[] memory) {
        return allCertificateHashes;
    }
}
