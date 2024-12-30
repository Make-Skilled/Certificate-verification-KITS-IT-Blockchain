// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract certi {
    // Struct to represent a user
    struct User {
        string fullName;
        string email;
        string password; // In practice, use a hash of the password
        string username;
    }

    // Mapping to store users by their Ethereum address
    mapping(address => User) private users;

    // Mapping to ensure unique usernames
    mapping(string => bool) private usernames;

    // Event to log the addition of a new user
    event UserAdded(address indexed userAddress, string fullName, string email, string username);

    // Function to add a new user
    function addUser(string memory fullName, string memory email, string memory password, string memory username) public {
        // Ensure the email, fullName, password, and username are not empty
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

        // Emit an event to log the addition of the new user
        emit UserAdded(msg.sender, fullName, email, username);
    }

    // Function to fetch user details
    function getUser(address userAddress)
        public
        view
        returns (string memory fullName, string memory email, string memory username)
    {
        User memory user = users[userAddress];
        require(bytes(user.email).length > 0, "User not found.");
        return (user.fullName, user.email, user.username);
    }
}
