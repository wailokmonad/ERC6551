pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/utils/ERC721Holder.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

interface IERC6551Account {
    receive() external payable;

    function token()
        external
        view
        returns (uint256 chainId, address tokenContract, uint256 tokenId);

    function state() external view returns (uint256);

    function isValidSigner(address signer, bytes calldata context)
        external
        view
        returns (bytes4 magicValue);
}

interface IERC6551Executable {
    function execute(address to, uint256 value, bytes calldata data, uint8 operation)
        external
        payable
        returns (bytes memory);
}

contract ERC6551Account is IERC165, IERC1271, ERC721Holder, ReentrancyGuard, IERC6551Account, IERC6551Executable {
    uint256 public state;

    receive() external payable {}

    modifier isValidSignerModifier() {
        require(_isValidSigner(msg.sender), "Invalid signer");
        _;
    }

    function execute(address to, uint256 value, bytes calldata data, uint8 operation) isValidSignerModifier
        external
        payable
        virtual
        returns (bytes memory result)
    {
        require(operation == 0, "Only call operations are supported");

        ++state;

        bool success;
        (success, result) = to.call{value: value}(data);

        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function isValidSigner(address signer, bytes calldata) external view virtual returns (bytes4) {
        if (_isValidSigner(signer)) {
            return IERC6551Account.isValidSigner.selector;
        }

        return bytes4(0);
    }

    function isValidSignature(bytes32 hash, bytes memory signature)
        external
        view
        virtual
        returns (bytes4 magicValue)
    {
        bool isValid = SignatureChecker.isValidSignatureNow(owner(), hash, signature);

        if (isValid) {
            return IERC1271.isValidSignature.selector;
        }

        return bytes4(0);
    }

    function supportsInterface(bytes4 interfaceId) external pure virtual returns (bool) {
        return interfaceId == type(IERC165).interfaceId
            || interfaceId == type(IERC6551Account).interfaceId
            || interfaceId == type(IERC6551Executable).interfaceId;
    }

    function token() public view virtual returns (uint256, address, uint256) {
        bytes memory footer = new bytes(0x60);

        assembly {
            extcodecopy(address(), add(footer, 0x20), 0x4d, 0x60)
        }

        return abi.decode(footer, (uint256, address, uint256));
    }

    function owner() public view virtual returns (address) {
        (uint256 chainId, address tokenContract, uint256 tokenId) = token();
        if (chainId != block.chainid) return address(0);

        return IERC721(tokenContract).ownerOf(tokenId);
    }

    function _isValidSigner(address signer) internal view virtual returns (bool) {
        return signer == owner();
    }

    function transferERC20(address tokenAddress, address to, uint256 amount) external nonReentrant {
        IERC20(tokenAddress).transfer(to, amount);
    }

    function approveERC20(address tokenAddress, address spender, uint256 amount) external nonReentrant {
        IERC20(tokenAddress).approve(spender, amount);
    }

    function transferERC721(address tokenAddress, address to, uint256 tokenId) external nonReentrant isValidSignerModifier {
        IERC721(tokenAddress).safeTransferFrom(address(this), to, tokenId);
    }

    function approveERC721(address tokenAddress, address to, uint256 tokenId) external nonReentrant isValidSignerModifier {
        IERC721(tokenAddress).approve(to, tokenId);
    }

    function transferERC1155Token(address tokenAddress, address to, uint256 tokenId, uint256 quantity, bytes memory data) external nonReentrant isValidSignerModifier {
        IERC1155(tokenAddress).safeTransferFrom(address(this), to, tokenId, quantity, data);
    }

    function transferERC1155Tokens(address tokenAddress, address to, uint256[] memory tokenIds, uint256[] memory quantities, bytes memory data) external nonReentrant isValidSignerModifier {
        IERC1155(tokenAddress).safeBatchTransferFrom(address(this), to, tokenIds, quantities, data);
    }

    function setApprovalForAllERC1155(address tokenAddress, address operator, bool approved) external nonReentrant isValidSignerModifier {
        IERC1155(tokenAddress).setApprovalForAll(operator, approved);
    }

    function transferEther(address payable to, uint256 amount) external nonReentrant isValidSignerModifier {
        (bool success, ) = to.call{value: amount}("");
        require(success, "Ether transfer failed");
    }
}