// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {XMSS} from "../../src/XMSS.sol";
import {IXmssVerifier, XmssVerifier} from "../src/XmssVerifier.sol";

/// Every normative claim `reference/eips/ERCS/erc-draft-xmss-verification.md` makes about the wire
/// format and the accept/reject behaviour of a conforming verifier, executed.
///
/// The standard states an exact encoded length; a spec that states a number nobody
/// runs is a number that drifts.
contract XmssVerifierTest is Test {
    XmssVerifier verifier;

    function setUp() public {
        verifier = new XmssVerifier();
    }

    /// `abi.encode(XMSS.Signature)` is 2304 + 32 * h bytes — the standard's formula.
    function test_encodedSignatureLength() public pure {
        assertEq(_encodedLength(10), 2624, "XMSS-SHA2_10_256");
        assertEq(_encodedLength(16), 2816, "XMSS-SHA2_16_256");
        assertEq(_encodedLength(20), 2944, "XMSS-SHA2_20_256");
        for (uint32 h = 1; h <= 20; ++h) {
            assertEq(_encodedLength(h), 2304 + 32 * uint256(h), "2304 + 32h");
        }
    }

    function test_verifiesAGenuineSignature() public view {
        (bytes32 digest, bytes32 root, bytes32 seed, bytes memory sig) = _vector();
        assertTrue(verifier.verifyXmssSignature(digest, root, seed, 10, sig), "genuine signature accepted");
    }

    function test_rejectsAFlippedBit() public view {
        (bytes32 digest, bytes32 root, bytes32 seed, bytes memory sig) = _vector();
        sig[2000] = bytes1(uint8(sig[2000]) ^ 0x01); // inside the WOTS+ signature
        assertFalse(verifier.verifyXmssSignature(digest, root, seed, 10, sig), "mutated signature rejected");
    }

    function test_rejectsAnotherDigest() public view {
        (bytes32 digest, bytes32 root, bytes32 seed, bytes memory sig) = _vector();
        assertFalse(
            verifier.verifyXmssSignature(keccak256("a different message"), root, seed, 10, sig), "digest is bound"
        );
    }

    /// The height is an input, not a field of the signature: a signature under a
    /// height-10 key must not verify when the caller claims another height.
    function test_rejectsAHeightThatIsNotTheKeysHeight() public view {
        (bytes32 digest, bytes32 root, bytes32 seed, bytes memory sig) = _vector();
        assertFalse(verifier.verifyXmssSignature(digest, root, seed, 9, sig), "height 9 rejected");
        assertFalse(verifier.verifyXmssSignature(digest, root, seed, 11, sig), "height 11 rejected");
    }

    function test_rejectsOutOfDomainParameters() public view {
        (bytes32 digest, bytes32 root, bytes32 seed, bytes memory sig) = _vector();
        assertFalse(verifier.verifyXmssSignature(digest, root, seed, 0, sig), "height 0");
        assertFalse(verifier.verifyXmssSignature(digest, root, seed, 21, sig), "height above MAX_HEIGHT");
        assertFalse(verifier.verifyXmssSignature(digest, bytes32(0), seed, 10, sig), "zero root");
        assertFalse(verifier.verifyXmssSignature(digest, root, bytes32(0), 10, sig), "zero seed");
    }

    /// A wrong-length blob is refused without reverting, so a caller cannot be griefed
    /// into a revert by a malformed third-party signature.
    function test_rejectsAWrongLengthEncoding() public view {
        (bytes32 digest, bytes32 root, bytes32 seed, bytes memory sig) = _vector();
        bytes memory short_ = new bytes(sig.length - 1);
        for (uint256 i = 0; i < short_.length; ++i) {
            short_[i] = sig[i];
        }
        assertFalse(verifier.verifyXmssSignature(digest, root, seed, 10, short_), "truncated");
        assertFalse(verifier.verifyXmssSignature(digest, root, seed, 10, ""), "empty");
    }

    function test_advertisesItsInterface() public view {
        // The standard quotes this identifier as a literal; a signature change here would
        // silently invalidate it ([XV-16]).
        assertEq(type(IXmssVerifier).interfaceId, bytes4(0x5867b896), "the identifier the ERC states");
        assertTrue(verifier.supportsInterface(type(IXmssVerifier).interfaceId), "IXmssVerifier");
        assertTrue(verifier.supportsInterface(type(IERC165).interfaceId), "IERC165");
        assertFalse(verifier.supportsInterface(0xffffffff), "the ERC-165 invalid id");
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    function _encodedLength(uint32 h) private pure returns (uint256) {
        XMSS.Signature memory sig;
        sig.authPath = new bytes32[](h);
        return abi.encode(sig).length;
    }

    /// The first signature of the library's height-10 test vector (`test/vectors/xmss_h10.json`,
    /// produced by `py/xmss_ref.py`), ABI-encoded the way the standard specifies.
    function _vector() private view returns (bytes32 digest, bytes32 root, bytes32 seed, bytes memory encoded) {
        string memory json = vm.readFile("test/vectors/xmss_h10.json");
        assertEq(vm.parseJsonUint(json, ".h"), 10, "the h = 10 vector");
        root = vm.parseJsonBytes32(json, ".root");
        seed = vm.parseJsonBytes32(json, ".seed");
        digest = vm.parseJsonBytes32(json, ".vectors[0].msg");

        XMSS.Signature memory sig;
        sig.leafIdx = uint32(vm.parseJsonUint(json, ".vectors[0].idx"));
        sig.r = vm.parseJsonBytes32(json, ".vectors[0].r");
        bytes32[] memory w = vm.parseJsonBytes32Array(json, ".vectors[0].wotsSig");
        for (uint256 i = 0; i < 67; ++i) {
            sig.wotsSig[i] = w[i];
        }
        sig.authPath = vm.parseJsonBytes32Array(json, ".vectors[0].auth");
        encoded = abi.encode(sig);
    }
}
