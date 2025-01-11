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
        address user;
        string hash;     // Hash of the certificate file
        string title;
        string filePath; // Path of the stored certificate
        bool exist;
    }

    mapping(address => Certificate[]) private userCertificates;
    mapping(address => Certificate[]) private organizationCertificates;

    // Function to add a certificate
    function addCertificate(address _issuer, address _user, string memory _hash, string memory _title, string memory _filePath) public {
        // Check if the certificate already exists for the issuer and user
        Certificate[] storage issuerCertificates = organizationCertificates[_issuer];
        for (uint i = 0; i < issuerCertificates.length; i++) {
            require(
                keccak256(abi.encodePacked(issuerCertificates[i].hash)) != keccak256(abi.encodePacked(_hash)),
                "Certificate already exists"
            );
        }

        // Create the new certificate
        Certificate memory new_certificate = Certificate({
            issuer: _issuer,
            user: _user,
            hash: _hash,
            title: _title,
            filePath: _filePath,
            exist: true
        });

        // Add the new certificate to the mappings
        userCertificates[_user].push(new_certificate);
        organizationCertificates[_issuer].push(new_certificate);
    }

    // Struct to represent a verification certificate
    struct VerificationCertificates {
        uint id;  // Auto-generated ID
        address issuedBy;
        address user;
        address organizationAddress;
        string username;
        string organizationName;
        string filepath;
        string status;
    }

    // Mappings to store verification certificates by user and organization
    mapping(address => VerificationCertificates[]) private userVerificationCertificates;
    mapping(address => VerificationCertificates[]) private organizationVerificationCertificates;

    // Counter for auto-generating unique IDs
    uint private certificateCounter;

    // Function to add a new verification certificate
    function addVerificationCertificate(
        address issuedBy,
        address user,
        address organizationAddress,
        string memory username,
        string memory organizationName,
        string memory filepath
    ) public {
        // Increment the counter to get a new unique ID
        certificateCounter++;

        // Create a new verification certificate with the auto-generated ID
        VerificationCertificates memory newCertificate = VerificationCertificates({
            id: certificateCounter,  // Assign the auto-generated ID
            issuedBy: issuedBy,
            user: user,
            organizationAddress: organizationAddress,
            username: username,
            organizationName: organizationName,
            filepath: filepath,
            status: "pending"  // Set the initial status to "pending"
        });

        // Store the certificate in the user's and organization's mapping
        userVerificationCertificates[user].push(newCertificate);
        organizationVerificationCertificates[organizationAddress].push(newCertificate);
    }

    // Function to update the status of a verification certificate
    function updateCertificateStatus(address organization, uint certificateId, string memory newStatus) public {
        // Find the certificate in the organization's list
        VerificationCertificates[] storage certificates = organizationVerificationCertificates[organization];
        bool updated = false;
        
        for (uint i = 0; i < certificates.length; i++) {
            if (certificates[i].id == certificateId) {
                certificates[i].status = newStatus;
                updated = true;
                break;
            }
        }
        
        require(updated, "Certificate not found.");
    }

    // Function to fetch user verification certificates
    function getUserVerificationCertificates(address user) public view returns (VerificationCertificates[] memory) {
        return userVerificationCertificates[user];
    }

    // Function to fetch organization verification certificates
    function getOrganizationVerificationCertificates(address organizationAddress) public view returns (VerificationCertificates[] memory) {
        return organizationVerificationCertificates[organizationAddress];
    }

    // Mapping to store users by their Ethereum address
    mapping(address => User) private users;

    // Mapping to ensure unique usernames
    mapping(string => bool) private usernames;

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

    // Function to fetch certificates for a specific address
    function getCertificates(address userAddress) public view returns (Certificate[] memory) {
        return userCertificates[userAddress];
    }

    // Function to fetch all certificates for a specific organization
    function getOrganizationCertificates(address _issuer) public view returns (Certificate[] memory) {
        return organizationCertificates[_issuer];
    }

    // Function to fetch the username by address
    function getUsername(address userAddress) public view returns (string memory) {
        // Ensure the user exists
        require(bytes(users[userAddress].email).length > 0, "User does not exist.");
        
        return users[userAddress].username;
    }

    // Function to check if a hash already exists in the user's certificates
    function checkHashExists(address organizationAddress, string memory hash) public view returns (string memory) {
        Certificate[] storage certificates = organizationCertificates[organizationAddress];
        
        for (uint i = 0; i < certificates.length; i++) {
            if (keccak256(abi.encodePacked(certificates[i].hash)) == keccak256(abi.encodePacked(hash))) {
                return "Certificate hash exists";
            }
        }
        
        return "Certificate hash does not exist";
    }
}
