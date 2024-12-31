// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract certi {
    // Struct to represent a user
    struct User {
        string fullName;
        string email;
        string password; // Store hashed password
        string username;
    }

    // Struct to represent a certificate
    struct Certificate {
        address owner;
        string hash; // Unique hash for the certificate
        string filePath; // File path for the certificate
    }

    // Mapping to store users by their Ethereum address
    mapping(address => User) private users;

    // Mapping to ensure unique usernames
    mapping(string => bool) private usernames;

    // Mapping to store certificates by their hash
    mapping(string => Certificate) private certificates;

    // Mapping to store certificates associated with a user's address
    mapping(address => Certificate[]) private user_certificates;

    // Array to store all certificate hashes
    string[] private allCertificateHashes;

    // Function to add a new user
    function addUser(
        string memory fullName, 
        string memory email, 
        string memory password, 
        string memory username
    ) public {
        require(bytes(fullName).length > 0, "Full name is required.");
        require(bytes(email).length > 0, "Email is required.");
        require(bytes(password).length > 0, "Password is required.");
        require(bytes(username).length > 0, "Username is required.");

        require(bytes(users[msg.sender].email).length == 0, "User already registered.");
        require(!usernames[username], "Username already taken.");

        users[msg.sender] = User(fullName, email, password, username);
        usernames[username] = true;
    }

    // Function to fetch user details
    function getUser(address userAddress)
        public
        view
        returns (string memory fullName, string memory email, string memory username, string memory password)
    {
        User memory user = users[userAddress];
        require(bytes(user.email).length > 0, "User not found.");
        return (user.fullName, user.email, user.username, user.password);
    }

    // Function to add a certificate
    function addCertificate(string memory hash, string memory filePath) public {
        require(bytes(hash).length > 0, "Certificate hash is required.");
        require(bytes(filePath).length > 0, "File path is required.");
        require(bytes(certificates[hash].hash).length == 0, "Certificate already exists.");

        certificates[hash] = Certificate(msg.sender, hash, filePath);
        user_certificates[msg.sender].push(certificates[hash]);
        allCertificateHashes.push(hash);
    }

    // Function to get certificate details
    function getCertificate(string memory hash)
        public
        view
        returns (address owner, string memory filePath)
    {
        Certificate memory certificate = certificates[hash];
        require(bytes(certificate.hash).length > 0, "Certificate not found.");
        return (certificate.owner, certificate.filePath);
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
        uint256 count = 0;

        for (uint256 i = 0; i < allCertificateHashes.length; i++) {
            string memory certificateHash = allCertificateHashes[i];
            if (certificates[certificateHash].owner == userAddress) {
                count++;
            }
        }

        Certificate[] memory userCertificates = new Certificate[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < allCertificateHashes.length; i++) {
            string memory certificateHash = allCertificateHashes[i];
            if (certificates[certificateHash].owner == userAddress) {
                userCertificates[index] = certificates[certificateHash];
                index++;
            }
        }

        return userCertificates;
    }

    // Function to delete a certificate
    function deleteCertificate(string memory hash) public {
        Certificate memory cert = certificates[hash];
        require(bytes(cert.hash).length > 0, "Certificate not found.");
        require(cert.owner == msg.sender, "Only the owner can delete the certificate.");

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
}
