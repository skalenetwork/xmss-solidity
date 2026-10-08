// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {XMSS} from "../src/XMSS.sol";
import {XMSSMT} from "../src/XMSSMT.sol";

contract XMSSMTWrapper {
    function verify(bytes32 m, XMSSMT.Signature memory sig, XMSS.PublicKey memory pk, uint256 h, uint256 d)
        external
        view
        returns (bool)
    {
        return XMSSMT.verify(m, sig, pk, h, d);
    }

    function verifyEncoded(bytes32 m, bytes memory enc, XMSS.PublicKey memory pk, uint256 h, uint256 d)
        external
        view
        returns (bool)
    {
        return XMSSMT.verifyEncoded(m, enc, pk, h, d);
    }

    function decode(bytes memory enc, uint256 h, uint256 d) external pure returns (bool, XMSSMT.Signature memory) {
        return XMSSMT.decode(enc, h, d);
    }
}

/// Vectors: test/vectors/xmssmt_h{h}_d{d}.json from py/xmssmt_ref.py. The four RFC 8391
/// sets among them are accepted by the RFC authors' C implementation and rejected with a
/// tampered message (scripts/crosscheck_reference.sh); (4, 2) is a small non-standard set
/// for fuzzing.
contract XMSSMTTest is Test {
    XMSSMTWrapper wrapper;

    function setUp() public {
        wrapper = new XMSSMTWrapper();
    }

    struct Vec {
        bytes32 m;
        XMSSMT.Signature sig;
        XMSS.PublicKey pk;
        bytes encoded;
        uint256 h;
        uint256 d;
    }

    function _file(uint256 h, uint256 d) internal pure returns (string memory) {
        return string.concat("test/vectors/xmssmt_h", vm.toString(h), "_d", vm.toString(d), ".json");
    }

    function load(uint256 h, uint256 d, uint256 i) internal view returns (Vec memory v) {
        string memory json = vm.readFile(_file(h, d));
        assertEq(vm.parseJsonUint(json, ".h"), h);
        assertEq(vm.parseJsonUint(json, ".d"), d);
        v.h = h;
        v.d = d;
        v.pk.root = vm.parseJsonBytes32(json, ".root");
        v.pk.seed = vm.parseJsonBytes32(json, ".seed");
        string memory base = string.concat(".vectors[", vm.toString(i), "]");
        v.sig.idx = uint64(vm.parseJsonUint(json, string.concat(base, ".idx")));
        v.sig.r = vm.parseJsonBytes32(json, string.concat(base, ".r"));
        v.m = vm.parseJsonBytes32(json, string.concat(base, ".msg"));
        v.encoded = vm.parseJsonBytes(json, string.concat(base, ".encoded"));
        v.sig.layers = new XMSSMT.Layer[](d);
        for (uint256 j = 0; j < d; ++j) {
            string memory lb = string.concat(base, ".layers[", vm.toString(j), "]");
            bytes32[] memory w = vm.parseJsonBytes32Array(json, string.concat(lb, ".wotsSig"));
            for (uint256 k = 0; k < 67; ++k) v.sig.layers[j].wotsSig[k] = w[k];
            v.sig.layers[j].authPath = vm.parseJsonBytes32Array(json, string.concat(lb, ".auth"));
        }
    }

    function ok(Vec memory v) internal view returns (bool) {
        return wrapper.verify(v.m, v.sig, v.pk, v.h, v.d);
    }

    function runAll(uint256 h, uint256 d) internal view {
        for (uint256 i = 0; i < 4; ++i) {
            Vec memory v = load(h, d, i);
            assertTrue(ok(v), "valid vector rejected");
            assertTrue(wrapper.verifyEncoded(v.m, v.encoded, v.pk, h, d), "valid encoded vector rejected");
            assertFalse(wrapper.verify(bytes32(uint256(v.m) ^ 1), v.sig, v.pk, h, d), "other message accepted");
        }
    }

    // ── Every vector, every set ────────────────────────────────────────────

    function test_verify_h4_d2() public view { runAll(4, 2); }
    function test_verify_h20_d2() public view { runAll(20, 2); }  // XMSSMT-SHA2_20/2_256
    function test_verify_h20_d4() public view { runAll(20, 4); }  // XMSSMT-SHA2_20/4_256
    function test_verify_h40_d8() public view { runAll(40, 8); }  // XMSSMT-SHA2_40/8_256
    function test_verify_h60_d12() public view { runAll(60, 12); } // XMSSMT-SHA2_60/12_256: tree addresses up to 2^55

    /// The highest index of the 60-bit set: every layer's tree address is non-zero and
    /// the top one reaches bit 54, so the 8-byte tree address field is exercised.
    function test_verify_h60_d12_topIndex() public view {
        Vec memory v = load(60, 12, 2);
        assertEq(v.sig.idx, (uint64(1) << 60) - 1);
        assertTrue(ok(v));
    }

    // ── Decoding agrees with the structured form ───────────────────────────

    function test_decode_matchesStruct() public view {
        Vec memory v = load(20, 4, 3);
        (bool good, XMSSMT.Signature memory s) = wrapper.decode(v.encoded, 20, 4);
        assertTrue(good);
        assertEq(s.idx, v.sig.idx);
        assertEq(s.r, v.sig.r);
        assertEq(s.layers.length, 4);
        for (uint256 j = 0; j < 4; ++j) {
            for (uint256 k = 0; k < 67; ++k) assertEq(s.layers[j].wotsSig[k], v.sig.layers[j].wotsSig[k]);
            assertEq(s.layers[j].authPath.length, 5);
            for (uint256 k = 0; k < 5; ++k) assertEq(s.layers[j].authPath[k], v.sig.layers[j].authPath[k]);
        }
    }

    function test_reject_encodedWrongLength() public view {
        Vec memory v = load(20, 2, 0);
        bytes memory longer = bytes.concat(v.encoded, hex"00");
        assertFalse(wrapper.verifyEncoded(v.m, longer, v.pk, 20, 2));
        bytes memory shorter = new bytes(v.encoded.length - 1);
        for (uint256 i = 0; i < shorter.length; ++i) shorter[i] = v.encoded[i];
        assertFalse(wrapper.verifyEncoded(v.m, shorter, v.pk, 20, 2));
    }

    /// The index field of the encoding is ceil(h/8) bytes, so it can hold values at or
    /// above 2^h (here 2^20 in 3 bytes); those are not indices of the key.
    function test_reject_encodedIndexBeyondHeight() public view {
        Vec memory v = load(20, 2, 0);
        bytes memory e = v.encoded;
        e[0] = bytes1(uint8(e[0]) | 0x10); // sets bit 20 of the 24-bit index
        assertFalse(wrapper.verifyEncoded(v.m, e, v.pk, 20, 2));
    }

    // ── The caller's (h, d) is bound ───────────────────────────────────────

    function test_reject_wrongShape() public view {
        Vec memory v = load(20, 4, 1);
        assertFalse(wrapper.verify(v.m, v.sig, v.pk, 20, 2), "accepted as 20/2");
        assertFalse(wrapper.verify(v.m, v.sig, v.pk, 40, 4), "accepted as 40/4");
        assertFalse(wrapper.verify(v.m, v.sig, v.pk, 20, 5), "accepted as 20/5");
        assertFalse(wrapper.verifyEncoded(v.m, v.encoded, v.pk, 20, 2), "encoded accepted as 20/2");
    }

    function test_lenMatchesXMSS() public pure {
        assertEq(XMSSMT.LEN, XMSS.LEN);
    }

    function test_reject_invalidParams() public pure {
        assertFalse(XMSSMT.validParams(20, 1)); // one layer is XMSS, not XMSS^MT
        assertFalse(XMSSMT.validParams(20, 0));
        assertFalse(XMSSMT.validParams(21, 2)); // layers must divide the height
        assertFalse(XMSSMT.validParams(64, 4)); // total above 60
        assertFalse(XMSSMT.validParams(42, 2)); // trees above 20
        assertTrue(XMSSMT.validParams(60, 3));
        assertTrue(XMSSMT.validParams(40, 2));
        assertTrue(XMSSMT.validParams(4, 2));
    }

    function test_reject_layerCountMismatch() public view {
        Vec memory v = load(20, 4, 0);
        XMSSMT.Layer[] memory three = new XMSSMT.Layer[](3);
        for (uint256 j = 0; j < 3; ++j) three[j] = v.sig.layers[j];
        v.sig.layers = three;
        assertFalse(ok(v));
    }

    function test_reject_authPathLengthMismatch() public view {
        Vec memory v = load(20, 4, 0);
        bytes32[] memory shorter = new bytes32[](4);
        for (uint256 k = 0; k < 4; ++k) shorter[k] = v.sig.layers[2].authPath[k];
        v.sig.layers[2].authPath = shorter;
        assertFalse(ok(v));
    }

    function test_reject_indexOutOfRange() public view {
        Vec memory v = load(20, 2, 0);
        v.sig.idx = uint64(1) << 20;
        assertFalse(ok(v));
    }

    function test_reject_zeroRootOrSeed() public view {
        Vec memory v = load(20, 2, 0);
        bytes32 root = v.pk.root;
        v.pk.root = 0;
        assertFalse(ok(v));
        v.pk.root = root;
        v.pk.seed = 0;
        assertFalse(ok(v));
    }

    // ── Every part of every layer is bound ─────────────────────────────────

    function test_reject_tamperEachLayer() public view {
        for (uint256 j = 0; j < 4; ++j) {
            Vec memory v = load(20, 4, 3);
            v.sig.layers[j].wotsSig[j * 11] ^= bytes32(uint256(1));
            assertFalse(ok(v), "tampered WOTS+ chain accepted");
            v = load(20, 4, 3);
            v.sig.layers[j].authPath[j % 5] ^= bytes32(uint256(1) << 200);
            assertFalse(ok(v), "tampered auth node accepted");
        }
    }

    /// Layers are not interchangeable: each layer's addresses carry its layer number,
    /// so the same signatures in another order fail, here the top two swapped.
    function test_reject_swappedLayers() public view {
        Vec memory v = load(20, 4, 3);
        XMSSMT.Layer memory top = v.sig.layers[3];
        v.sig.layers[3] = v.sig.layers[2];
        v.sig.layers[2] = top;
        assertFalse(ok(v));
    }

    /// Two indices whose bottom leaf is the same but whose bottom tree differs (idx and
    /// idx + 2^(h/d)) are distinct one-time keys: a signature for one is not one for
    /// the other, because the tree address is part of every hash address.
    function test_reject_sameLeafOtherTree() public view {
        Vec memory v = load(20, 2, 3);
        v.sig.idx += uint64(1) << 10;
        assertFalse(ok(v));
    }

    function test_reject_wrongR() public view {
        Vec memory v = load(40, 8, 1);
        v.sig.r ^= bytes32(uint256(1));
        assertFalse(ok(v));
    }

    function test_reject_crossKey() public view {
        Vec memory a = load(20, 2, 0);
        Vec memory b = load(20, 4, 0);
        a.pk = b.pk;
        assertFalse(ok(a));
    }

    // ── Fuzz, on the small set ─────────────────────────────────────────────

    function testFuzz_reject_otherMessage(bytes32 forged) public view {
        Vec memory v = load(4, 2, 1);
        vm.assume(forged != v.m);
        assertFalse(wrapper.verify(forged, v.sig, v.pk, 4, 2));
    }

    function testFuzz_reject_otherIndex(uint64 idx) public view {
        Vec memory v = load(4, 2, 3);
        vm.assume(idx != v.sig.idx);
        v.sig.idx = idx;
        assertFalse(ok(v));
    }

    function testFuzz_reject_bitflip(uint8 vec, uint8 layer, uint8 element, uint8 bit, bool inAuth) public view {
        Vec memory v = load(4, 2, vec % 4);
        uint256 j = layer % 2;
        if (inAuth) {
            v.sig.layers[j].authPath[element % 2] ^= bytes32(uint256(1) << bit);
        } else {
            v.sig.layers[j].wotsSig[element % 67] ^= bytes32(uint256(1) << bit);
        }
        assertFalse(ok(v));
    }

    function testFuzz_reject_encodedByteFlip(uint8 vec, uint256 pos, uint8 mask) public view {
        vm.assume(mask != 0);
        Vec memory v = load(4, 2, vec % 4);
        pos = bound(pos, 0, v.encoded.length - 1);
        v.encoded[pos] = bytes1(uint8(v.encoded[pos]) ^ mask);
        assertFalse(wrapper.verifyEncoded(v.m, v.encoded, v.pk, 4, 2));
    }

    // ── Gas ─────────────────────────────────────────────────────────────────

    function _gas(uint256 h, uint256 d) internal returns (uint256 used) {
        Vec memory v = load(h, d, 3);
        uint256 g = gasleft();
        bool good = wrapper.verify(v.m, v.sig, v.pk, h, d);
        used = g - gasleft();
        assertTrue(good);
    }

    function test_gas_perSet() public {
        console.log("XMSSMT-SHA2_20/2_256  verify gas:", _gas(20, 2));
        console.log("XMSSMT-SHA2_20/4_256  verify gas:", _gas(20, 4));
        console.log("XMSSMT-SHA2_40/8_256  verify gas:", _gas(40, 8));
        console.log("XMSSMT-SHA2_60/12_256 verify gas:", _gas(60, 12));
    }
}
