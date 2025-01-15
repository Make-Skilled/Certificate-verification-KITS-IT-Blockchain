// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract Certi {
    struct User {
        string fullName;
        string email;
        string password; // Store hashed password
        string username;
        string usertype; // User type field
    }

    struct Certificate {
        address issuer;
        address user;
        string hash;
        string title;
        string filePath;
        bool exist;
    }

    struct VerificationCertificates {
        uint id;
        address issuedBy;
        address user;
        address organizationAddress;
        string username;
        string organizationName;
        string filepath;
        string status;
        bool request_sent;
    }

    mapping(address => Certificate[]) private userCertificates;
    mapping(address => Certificate[]) private organizationCertificates;

    mapping(address => VerificationCertificates[])
        private userVerificationCertificates;
    mapping(address => VerificationCertificates[])
        private organizationVerificationCertificates;
    mapping(uint => VerificationCertificates) private certificates;
    uint private certificateCounter;

    function updateCertificateStatus(
        uint _certificateId,
        string memory _newStatus
    ) public {
        // Update the status in the certificates mapping
        VerificationCertificates storage certificate = certificates[
            _certificateId
        ];
        require(certificate.id != 0, "Certificate not found.");
        certificate.status = _newStatus;

        // Find and update the status in organizationVerificationCertificates
        address orgAddress = certificate.organizationAddress;
        VerificationCertificates[]
            storage orgCerts = organizationVerificationCertificates[orgAddress];

        for (uint i = 0; i < orgCerts.length; i++) {
            if (orgCerts[i].id == _certificateId) {
                orgCerts[i].status = _newStatus;
                break;
            }
        }
    }

    mapping(address => User) private users;
    mapping(string => bool) private usernames;

    // Function to add a certificate
    function addCertificate(
        address _issuer,
        address _user,
        string memory _hash,
        string memory _title,
        string memory _filePath
    ) public {
        Certificate[] storage issuerCertificates = organizationCertificates[
            _issuer
        ];
        for (uint i = 0; i < issuerCertificates.length; i++) {
            require(
                keccak256(abi.encodePacked(issuerCertificates[i].hash)) !=
                    keccak256(abi.encodePacked(_hash)),
                "Certificate already exists"
            );
        }

        Certificate memory newCertificate = Certificate({
            issuer: _issuer,
            user: _user,
            hash: _hash,
            title: _title,
            filePath: _filePath,
            exist: true
        });

        userCertificates[_user].push(newCertificate);
        organizationCertificates[_issuer].push(newCertificate);
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

        VerificationCertificates
            memory newCertificate = VerificationCertificates({
                id: certificateCounter,
                issuedBy: _issuedBy,
                user: _user,
                organizationAddress: _organizationAddress,
                username: _username,
                organizationName: _organizationName,
                filepath: _filepath,
                status: "pending",
                request_sent: false
            });

        userVerificationCertificates[_user].push(newCertificate);
        organizationVerificationCertificates[_organizationAddress].push(
            newCertificate
        );
        certificates[certificateCounter] = newCertificate;
    }

    // Function to change the request_sent status of a certificate by ID
    function changeRequestSentStatus(uint _id, bool _newStatus) public {
        require(certificates[_id].id != 0, "Certificate not found.");

        certificates[_id].request_sent = _newStatus;

        VerificationCertificates[]
            storage userCerts = userVerificationCertificates[
                certificates[_id].user
            ];
        for (uint i = 0; i < userCerts.length; i++) {
            if (userCerts[i].id == _id) {
                userCerts[i].request_sent = _newStatus;
                break;
            }
        }

        VerificationCertificates[]
            storage orgCerts = organizationVerificationCertificates[
                certificates[_id].organizationAddress
            ];
        for (uint i = 0; i < orgCerts.length; i++) {
            if (orgCerts[i].id == _id) {
                orgCerts[i].request_sent = _newStatus;
                break;
            }
        }
    }

    // Function to fetch all certificates where request_sent is true
    function getAllRequestSentTrue()
        public
        view
        returns (VerificationCertificates[] memory)
    {
        uint count = 0;
        for (uint i = 1; i <= certificateCounter; i++) {
            if (certificates[i].request_sent) {
                count++;
            }
        }

        VerificationCertificates[]
            memory result = new VerificationCertificates[](count);
        uint index = 0;
        for (uint i = 1; i <= certificateCounter; i++) {
            if (certificates[i].request_sent) {
                result[index] = certificates[i];
                index++;
            }
        }
        return result;
    }

    // Function to fetch user verification certificates
    function getUserVerificationCertificates(
        address _user
    ) public view returns (VerificationCertificates[] memory) {
        return userVerificationCertificates[_user];
    }

    // Function to fetch organization verification certificates
    function getOrganizationVerificationCertificates(
        address _organizationAddress
    ) public view returns (VerificationCertificates[] memory) {
        return organizationVerificationCertificates[_organizationAddress];
    }

    // Function to fetch details by ID
    function getCertificateById(
        uint _id
    )
        public
        view
        returns (
            uint,
            address,
            address,
            address,
            string memory,
            string memory,
            string memory,
            string memory
        )
    {
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

    // Function to add a new user
    function addUser(
        string memory _fullName,
        string memory _email,
        string memory _password,
        string memory _username,
        string memory _usertype
    ) public {
        require(
            bytes(users[msg.sender].email).length == 0,
            "User already registered."
        );
        require(!usernames[_username], "Username already taken.");

        users[msg.sender] = User(
            _fullName,
            _email,
            _password,
            _username,
            _usertype
        );
        usernames[_username] = true;
    }

    // Function to fetch user details
    function getUser(
        address _userAddress
    )
        public
        view
        returns (
            string memory fullName,
            string memory email,
            string memory username,
            string memory password,
            string memory usertype
        )
    {
        User memory user = users[_userAddress];
        require(bytes(user.email).length > 0, "User not found.");
        return (
            user.fullName,
            user.email,
            user.username,
            user.password,
            user.usertype
        );
    }

    // Function to fetch certificates for a specific user
    function getCertificates(
        address _userAddress
    ) public view returns (Certificate[] memory) {
        return userCertificates[_userAddress];
    }

    // Function to fetch all certificates for a specific organization
    function getOrganizationCertificates(
        address _issuer
    ) public view returns (Certificate[] memory) {
        return organizationCertificates[_issuer];
    }

    // Function to fetch the username by address
    function getUsername(
        address _userAddress
    ) public view returns (string memory) {
        require(
            bytes(users[_userAddress].email).length > 0,
            "User does not exist."
        );
        return users[_userAddress].username;
    }

    // Function to check if a hash already exists in the user's certificates
    function checkHashExists(
        address _organizationAddress,
        string memory _hash
    ) public view returns (string memory) {
        Certificate[] storage certificates = organizationCertificates[
            _organizationAddress
        ];
        for (uint i = 0; i < certificates.length; i++) {
            if (
                keccak256(abi.encodePacked(certificates[i].hash)) ==
                keccak256(abi.encodePacked(_hash))
            ) {
                return "Certificate hash exists";
            }
        }
        return "Certificate hash does not exist";
    }
}
