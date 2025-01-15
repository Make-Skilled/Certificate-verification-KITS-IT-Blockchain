// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract Certi {
    // Struct to represent a user
    struct OrganizationRequests {
        uint id;
        address issuer;
        address organization;
    }

    mapping(address => OrganizationRequests[]) private issuerMapping;
    mapping(address => OrganizationRequests[]) private organizationMapping;

    // Function to add an organization request
    function addOrganizationRequest(
        uint _id,
        address _issuerAddress,
        address _organizationAddress
    ) public {
        OrganizationRequests memory newRequest = OrganizationRequests({
            id: _id,
            issuer: _issuerAddress,
            organization: _organizationAddress
        });

        issuerMapping[_issuerAddress].push(newRequest);
        organizationMapping[_organizationAddress].push(newRequest);
    }

    // Function to retrieve requests for an issuer
    function getRequestsByIssuer(address _issuerAddress) public view returns (OrganizationRequests[] memory) {
        return issuerMapping[_issuerAddress];
    }

    // Function to retrieve requests for an organization
    function getRequestsByOrganization(address _organizationAddress) public view returns (OrganizationRequests[] memory) {
        return organizationMapping[_organizationAddress];
    }

    struct User {
        string fullName;
        string email;
        string password; // Store hashed password
        string username;
        string usertype; // User type field
    }

    // Struct to represent a certificate
    struct Certificate {
        address issuer;
        address user;
        string hash;
        string title;
        string filePath;
        bool exist;
    }

    mapping(address => Certificate[]) private userCertificates;
    mapping(address => Certificate[]) private organizationCertificates;

    // Function to add a certificate
    function addCertificate(
        address _issuer,
        address _user,
        string memory _hash,
        string memory _title,
        string memory _filePath
    ) public {
        // Check if the certificate already exists for the issuer and user
        Certificate[] storage issuerCertificates = organizationCertificates[_issuer];
        for (uint i = 0; i < issuerCertificates.length; i++) {
            require(
                keccak256(abi.encodePacked(issuerCertificates[i].hash)) != keccak256(abi.encodePacked(_hash)),
                "Certificate already exists"
            );
        }

        // Create the new certificate
        Certificate memory newCertificate = Certificate({
            issuer: _issuer,
            user: _user,
            hash: _hash,
            title: _title,
            filePath: _filePath,
            exist: true
        });

        // Add the new certificate to the mappings
        userCertificates[_user].push(newCertificate);
        organizationCertificates[_issuer].push(newCertificate);
    }

    // Struct to represent a verification certificate
    struct VerificationCertificates {
        uint id;
        address issuedBy;
        address user;
        address organizationAddress;
        string username;
        string organizationName;
        string filepath;
        string status;
    }

    // Mappings to store verification certificates
    mapping(address => VerificationCertificates[]) private userVerificationCertificates;
    mapping(address => VerificationCertificates[]) private organizationVerificationCertificates;
    mapping(uint => VerificationCertificates) private certificates;
    uint private certificateCounter;

    // Function to fetch details by ID
    function getCertificateById(uint _id) public view returns (
        uint,
        address,
        address,
        address,
        string memory,
        string memory,
        string memory,
        string memory
    ) {
        VerificationCertificates memory certificate = certificates[_id];
        return (
            certificate.id,
            certificate.issuedBy,
            certificate.user,
            certificate.organizationAddress,
            certificate.username,
            certificate.organizationName,
            certificate.filepath,
            certificate.status
        );
    }

    // Function to add a new verification certificate
    function addVerificationCertificate(
        address _issuedBy,
        address _user,
        address _organizationAddress,
        string memory _username,
        string memory _organizationName,
        string memory _filepath
    ) public {
        certificateCounter++;

        VerificationCertificates memory newCertificate = VerificationCertificates({
            id: certificateCounter,
            issuedBy: _issuedBy,
            user: _user,
            organizationAddress: _organizationAddress,
            username: _username,
            organizationName: _organizationName,
            filepath: _filepath,
            status: "pending"
        });

        userVerificationCertificates[_user].push(newCertificate);
        organizationVerificationCertificates[_organizationAddress].push(newCertificate);
        certificates[certificateCounter] = newCertificate;
    }

    // Function to update the status of a verification certificate
    function updateCertificateStatus(uint _certificateId, string memory _newStatus) public {
        VerificationCertificates storage certificate = certificates[_certificateId];
        require(certificate.id != 0, "Certificate not found.");
        certificate.status = _newStatus;
    }

    // Function to fetch user verification certificates
    function getUserVerificationCertificates(address _user) public view returns (VerificationCertificates[] memory) {
        return userVerificationCertificates[_user];
    }

    // Function to fetch organization verification certificates
    function getOrganizationVerificationCertificates(address _organizationAddress) public view returns (VerificationCertificates[] memory) {
        return organizationVerificationCertificates[_organizationAddress];
    }

    // Mapping to store users by their Ethereum address
    mapping(address => User) private users;
    mapping(string => bool) private usernames;

    // Function to add a new user
    function addUser(
        string memory _fullName, 
        string memory _email, 
        string memory _password, 
        string memory _username, 
        string memory _usertype
    ) public {
        require(bytes(users[msg.sender].email).length == 0, "User already registered.");
        require(!usernames[_username], "Username already taken.");

        users[msg.sender] = User(_fullName, _email, _password, _username, _usertype);
        usernames[_username] = true;
    }

    // Function to fetch user details
    function getUser(address _userAddress) public view returns (
        string memory fullName,
        string memory email,
        string memory username,
        string memory password,
        string memory usertype
    ) {
        User memory user = users[_userAddress];
        require(bytes(user.email).length > 0, "User not found.");
        return (user.fullName, user.email, user.username, user.password, user.usertype);
    }

    // Function to fetch certificates for a specific user
    function getCertificates(address _userAddress) public view returns (Certificate[] memory) {
        return userCertificates[_userAddress];
    }

    // Function to fetch all certificates for a specific organization
    function getOrganizationCertificates(address _issuer) public view returns (Certificate[] memory) {
        return organizationCertificates[_issuer];
    }

    // Function to fetch the username by address
    function getUsername(address _userAddress) public view returns (string memory) {
        require(bytes(users[_userAddress].email).length > 0, "User does not exist.");
        return users[_userAddress].username;
    }

    // Function to check if a hash already exists in the user's certificates
    function checkHashExists(address _organizationAddress, string memory _hash) public view returns (string memory) {
        Certificate[] storage certificates = organizationCertificates[_organizationAddress];
        
        for (uint i = 0; i < certificates.length; i++) {
            if (keccak256(abi.encodePacked(certificates[i].hash)) == keccak256(abi.encodePacked(_hash))) {
                return "Certificate hash exists";
            }
        }
        
        return "Certificate hash does not exist";
    }
}
