// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract BlockSafeguard {
    // Structure to store blocked IP information
    struct BlockedIP {
        string ip;
        string reason;
        uint256 timestamp;
    }

    // Array to store all blocked IPs
    BlockedIP[] public blacklist;

    // Event emitted when an IP is blocked
    event Blacklisted(
        string indexed ip,
        string reason,
        uint256 timestamp
    );

    /**
     * @dev Add an IP address to the blacklist
     * @param _ip The IP address to block
     * @param _reason The reason for blocking
     */
    function addIP(string memory _ip, string memory _reason) public {
        // Check if IP is already blocked (optional optimization)
        for (uint256 i = 0; i < blacklist.length; i++) {
            if (keccak256(abi.encodePacked(blacklist[i].ip)) == keccak256(abi.encodePacked(_ip))) {
                // IP already blocked, update reason and timestamp
                blacklist[i].reason = _reason;
                blacklist[i].timestamp = block.timestamp;
                emit Blacklisted(_ip, _reason, block.timestamp);
                return;
            }
        }

        // Add new blocked IP
        blacklist.push(BlockedIP({
            ip: _ip,
            reason: _reason,
            timestamp: block.timestamp
        }));

        emit Blacklisted(_ip, _reason, block.timestamp);
    }

    /**
     * @dev Get blocked IP information by index
     * @param index The index in the blacklist array
     * @return ip The blocked IP address
     * @return reason The reason for blocking
     * @return timestamp When the IP was blocked
     */
    function getIP(uint256 index) public view returns (
        string memory ip,
        string memory reason,
        uint256 timestamp
    ) {
        require(index < blacklist.length, "Index out of bounds");
        BlockedIP memory blocked = blacklist[index];
        return (blocked.ip, blocked.reason, blocked.timestamp);
    }

    /**
     * @dev Get the total number of blocked IPs
     * @return The length of the blacklist array
     */
    function getLength() public view returns (uint256) {
        return blacklist.length;
    }

    /**
     * @dev Check if an IP is currently blocked
     * @param _ip The IP address to check
     * @return True if the IP is blocked, false otherwise
     */
    function isBlocked(string memory _ip) public view returns (bool) {
        for (uint256 i = 0; i < blacklist.length; i++) {
            if (keccak256(abi.encodePacked(blacklist[i].ip)) == keccak256(abi.encodePacked(_ip))) {
                return true;
            }
        }
        return false;
    }

    /**
     * @dev Get all blocked IPs (use with caution for large lists)
     * @return Array of all blocked IPs
     */
    function getAllBlockedIPs() public view returns (BlockedIP[] memory) {
        return blacklist;
    }
}