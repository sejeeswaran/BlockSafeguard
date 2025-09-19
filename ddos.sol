// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Blacklist {
    struct Entry {
        string ip;
        string reason;
        uint256 timestamp;
    }

    Entry[] public blacklist;
    event Blacklisted(string ip, string reason, uint256 timestamp);

    function addIP(string memory ip, string memory reason) public {
        blacklist.push(Entry(ip, reason, block.timestamp));
        emit Blacklisted(ip, reason, block.timestamp);
    }

    function getIP(uint index) public view returns (string memory, string memory, uint256) {
        Entry memory e = blacklist[index];
        return (e.ip, e.reason, e.timestamp);
    }

    function getLength() public view returns (uint) {
        return blacklist.length;
    }
}
