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

    // Function to add a new user
    function addUser(
        string memory fullName, 
        string memory email, 
        string memory password, 
        string memory username
    ) public {
        // Ensure the fullName, email, password, and username are not empty
        require(bytes(fullName).length > 0, "Full name is required.");
        require(bytes(email).length > 0, "Email is required.");
        require(bytes(password).length > 0, "Password is required.");
        require(bytes(username).length > 0, "Username is required.");

        // Ensure the user is not already registered
        require(bytes(users[msg.sender].email).length == 0, "User already registered.");

        // Ensure the username is unique
        require(!usernames[username], "Username already taken.");

        // Add the user to the mapping
        users[msg.sender] = User(fullName, email, password, username);

        // Mark the username as used
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
        // Ensure the hash and filePath are not empty
        require(bytes(hash).length > 0, "Certificate hash is required.");
        require(bytes(filePath).length > 0, "File path is required.");

        // Ensure the certificate hash is unique
        require(bytes(certificates[hash].hash).length == 0, "Certificate already exists.");

        // Add the certificate to the mapping
        certificates[hash] = Certificate(msg.sender, hash, filePath);
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
}
