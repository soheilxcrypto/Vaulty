// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract FileRegistry {
    address public owner;
    uint256 public fileCount;

    struct File {
        string cid;
        address uploader;
    }

    // fileId -> File
    mapping(uint256 => File) public files;
    // fileId -> recipient -> encrypted AES key (bytes)
    mapping(uint256 => mapping(address => bytes)) private encryptedKeys;

    event FileAdded(uint256 indexed fileId, string cid, address indexed uploader);
    event KeyAssigned(uint256 indexed fileId, address indexed recipient, bytes encKey);
    event KeyRevoked(uint256 indexed fileId, address indexed recipient);

    modifier onlyOwner() {
        require(msg.sender == owner, "only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // add file + encrypted keys for recipients
    function addFile(string calldata cid, address[] calldata recipients, bytes[] calldata encKeys) external onlyOwner returns (uint256) {
        require(recipients.length == encKeys.length, "mismatch");
        uint256 id = ++fileCount;
        files[id] = File({ cid: cid, uploader: msg.sender });
        emit FileAdded(id, cid, msg.sender);

        for (uint i = 0; i < recipients.length; i++) {
            encryptedKeys[id][recipients[i]] = encKeys[i];
            emit KeyAssigned(id, recipients[i], encKeys[i]);
        }
        return id;
    }

    // owner can assign additional key later
    function assignKey(uint256 fileId, address recipient, bytes calldata encKey) external onlyOwner {
        encryptedKeys[fileId][recipient] = encKey;
        emit KeyAssigned(fileId, recipient, encKey);
    }

    function revokeKey(uint256 fileId, address recipient) external onlyOwner {
        delete encryptedKeys[fileId][recipient];
        emit KeyRevoked(fileId, recipient);
    }

    // read functions
    function getFile(uint256 fileId) external view returns (string memory cid, address uploader) {
        File storage f = files[fileId];
        return (f.cid, f.uploader);
    }

    function getEncryptedKey(uint256 fileId, address recipient) external view returns (bytes memory) {
        return encryptedKeys[fileId][recipient];
    }
}
