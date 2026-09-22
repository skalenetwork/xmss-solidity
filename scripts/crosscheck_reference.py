"""Convert test/vectors/xmss_h{10,20}.json to xmss-reference's wire format:
public key OID(4) || root || SEED; signed message idx(4) || r || wotsSig || auth || M."""
import json
import sys

vectors, out = sys.argv[1], sys.argv[2]
OID = {10: 1, 20: 3}  # XMSS-SHA2_10_256, XMSS-SHA2_20_256 (RFC 8391 section 5.3)
h = lambda s: bytes.fromhex(s[2:])
for height, oid in OID.items():
    d = json.load(open(f"{vectors}/xmss_h{height}.json"))
    assert d["h"] == height
    open(f"{out}/pk_h{height}.bin", "wb").write(oid.to_bytes(4, "big") + h(d["root"]) + h(d["seed"]))
    for i, v in enumerate(d["vectors"]):
        assert len(v["auth"]) == height and len(v["wotsSig"]) == 67
        sig = v["idx"].to_bytes(4, "big") + h(v["r"]) + b"".join(map(h, v["wotsSig"])) + b"".join(map(h, v["auth"]))
        msg = h(v["msg"])
        open(f"{out}/sm_h{height}_{i}.bin", "wb").write(sig + msg)
        bad = bytearray(msg)
        bad[-1] ^= 1
        open(f"{out}/sm_h{height}_{i}_tampered.bin", "wb").write(sig + bytes(bad))
