"""Convert test/vectors/xmssmt_h*_d*.json (the RFC 8391 parameter sets) to
xmss-reference's wire format: public key OID(4) || root || SEED; signed message
idx_sig(ceil(h/8)) || r || d x (wotsSig || auth) || M — the `encoded` field || M."""
import json
import sys

vectors, out = sys.argv[1], sys.argv[2]
OID = {(20, 2): 1, (20, 4): 2, (40, 8): 5, (60, 12): 8}  # XMSSMT-SHA2_h/d_256, RFC 8391 section 5.4.1
h = lambda s: bytes.fromhex(s[2:])
for (height, layers), oid in OID.items():
    d = json.load(open(f"{vectors}/xmssmt_h{height}_d{layers}.json"))
    assert (d["h"], d["d"]) == (height, layers)
    tag = f"mt_h{height}_d{layers}"
    open(f"{out}/pk_{tag}.bin", "wb").write(oid.to_bytes(4, "big") + h(d["root"]) + h(d["seed"]))
    for i, v in enumerate(d["vectors"]):
        sig, msg = h(v["encoded"]), h(v["msg"])
        assert len(sig) == (height + 7) // 8 + 32 + layers * (67 + height // layers) * 32
        assert len(v["layers"]) == layers
        open(f"{out}/sm_{tag}_{i}.bin", "wb").write(sig + msg)
        bad = bytearray(msg)
        bad[-1] ^= 1
        open(f"{out}/sm_{tag}_{i}_tampered.bin", "wb").write(sig + bytes(bad))
