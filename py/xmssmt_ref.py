#!/usr/bin/env python3
"""Clean-room XMSS^MT reference (RFC 8391 §4.2, SHA-256, n=32, w=16, len=67).

Generates test vectors for the Solidity verifier in src/XMSSMT.sol. It reuses the
keyed hash primitives and the WOTS+ message encoding of xmss_ref.py, which are
identical in XMSS and XMSS^MT, and adds what XMSS^MT changes: every address carries
a layer and a 64-bit tree address (§2.5), the message is hashed once with the full
index (Algorithm 16), and each of the d layers signs the root of the layer below.

Signer-side private-key derivation is implementation-defined (the verifier never
sees it); it includes the layer and tree address so no two trees share WOTS+ keys.

MIT licensed.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
import xmss_ref as x  # noqa: E402

N, W, LEN = x.N, x.W, x.LEN
sha, to_byte, PRF, F, H_msg, rand_hash = x.sha, x.to_byte, x.PRF, x.F, x.H_msg, x.rand_hash

# RFC 8391 §5.4.1, XMSS^MT with SHA2 and n = 32: OID -> (total height h, layers d).
OIDS = {1: (20, 2), 2: (20, 4), 3: (40, 2), 4: (40, 4), 5: (40, 8), 6: (60, 3), 7: (60, 6), 8: (60, 12)}


def adrs(layer: int, tree: int, typ: int, w4: int, w5: int, w6: int, kam: int) -> bytes:
    # layer(4) | tree(8) | type(4) | w4 | w5 | w6 | keyAndMask   (RFC 8391 §2.5)
    return to_byte(layer, 4) + to_byte(tree, 8) + to_byte(typ, 4) + to_byte(w4, 4) \
        + to_byte(w5, 4) + to_byte(w6, 4) + to_byte(kam, 4)


def chain(v: bytes, layer, tree, ots, cadr, start, steps, seed):
    for j in range(start, start + steps):
        key = PRF(seed, adrs(layer, tree, 0, ots, cadr, j, 0))
        bm = PRF(seed, adrs(layer, tree, 0, ots, cadr, j, 1))
        v = F(key, bytes(a ^ b for a, b in zip(v, bm)))
    return v


def wots_sk(sk_seed, layer, tree, leaf):
    return [sha(sk_seed + to_byte(layer, 4) + to_byte(tree, 8) + to_byte(leaf, 4) + to_byte(i, 4))
            for i in range(LEN)]


def wots_pk(sk_seed, layer, tree, leaf, seed):
    sk = wots_sk(sk_seed, layer, tree, leaf)
    return [chain(sk[i], layer, tree, leaf, i, 0, W - 1, seed) for i in range(LEN)]


def wots_sign(m, sk_seed, layer, tree, leaf, seed):
    sk = wots_sk(sk_seed, layer, tree, leaf)
    vals = x.base_w_with_csum(m)
    return [chain(sk[i], layer, tree, leaf, i, 0, vals[i], seed) for i in range(LEN)]


def ltree(pk, layer, tree, leaf, seed):
    nodes, height = list(pk), 0
    while len(nodes) > 1:
        nxt = [rand_hash(nodes[2 * i], nodes[2 * i + 1], seed, adrs(layer, tree, 1, leaf, height, i, 0))
               for i in range(len(nodes) // 2)]
        if len(nodes) & 1:
            nxt.append(nodes[-1])
        nodes, height = nxt, height + 1
    return nodes[0]


def build_tree(hp, layer, tree, sk_seed, seed):
    """All levels of the XMSS tree at (layer, tree); levels[hp][0] is its root."""
    leaves = [ltree(wots_pk(sk_seed, layer, tree, i, seed), layer, tree, i, seed) for i in range(1 << hp)]
    levels = [leaves]
    for k in range(hp):
        cur = levels[-1]
        levels.append([rand_hash(cur[2 * i], cur[2 * i + 1], seed, adrs(layer, tree, 2, 0, k, i, 0))
                       for i in range(len(cur) // 2)])
    return levels


class Key:
    def __init__(self, h, d, label):
        assert h % d == 0
        self.h, self.d, self.hp = h, d, h // d
        self.seed = sha(b"xmssmt/public-seed/" + label)
        self.sk_seed = sha(b"xmssmt/sk-seed/" + label)
        self.sk_prf = sha(b"xmssmt/sk-prf/" + label)
        self._trees = {}
        self.root = self.tree(d - 1, 0)[self.hp][0]

    def tree(self, layer, tree):
        if (layer, tree) not in self._trees:
            self._trees[(layer, tree)] = build_tree(self.hp, layer, tree, self.sk_seed, self.seed)
        return self._trees[(layer, tree)]

    def sign(self, msg32: bytes, idx: int):
        """RFC 8391 Algorithm 15 (XMSSMT_sign), with the layer trees built on demand."""
        r = sha(self.sk_prf + to_byte(idx, 32))
        m = H_msg(r + self.root + to_byte(idx, N), msg32)
        layers, idx_tree = [], idx
        for j in range(self.d):
            idx_leaf = idx_tree & ((1 << self.hp) - 1)
            idx_tree >>= self.hp
            levels = self.tree(j, idx_tree)
            sig_ots = wots_sign(m, self.sk_seed, j, idx_tree, idx_leaf, self.seed)
            auth = [levels[k][(idx_leaf >> k) ^ 1] for k in range(self.hp)]
            layers.append((sig_ots, auth))
            m = levels[self.hp][0]  # the next layer signs this tree's root
        return r, layers


def root_from_sig(idx_leaf, sig_ots, auth, m, seed, layer, tree):
    """RFC 8391 Algorithm 13 (XMSS_rootFromSig) with the layer/tree address of the caller."""
    vals = x.base_w_with_csum(m)
    pk = [chain(sig_ots[i], layer, tree, idx_leaf, i, vals[i], W - 1 - vals[i], seed) for i in range(LEN)]
    node, ti = ltree(pk, layer, tree, idx_leaf, seed), idx_leaf
    for k in range(len(auth)):
        ti >>= 1
        pair = (node, auth[k]) if (idx_leaf >> k) & 1 == 0 else (auth[k], node)
        node = rand_hash(pair[0], pair[1], seed, adrs(layer, tree, 2, 0, k, ti, 0))
    return node


def verify(h, d, msg32, idx, r, layers, root, seed):
    """RFC 8391 Algorithm 16 (XMSSMT_verify)."""
    if h % d or len(layers) != d or idx >= 1 << h:
        return False
    hp = h // d
    m = H_msg(r + root + to_byte(idx, N), msg32)
    idx_tree = idx
    for j, (sig_ots, auth) in enumerate(layers):
        if len(auth) != hp:
            return False
        idx_leaf = idx_tree & ((1 << hp) - 1)
        idx_tree >>= hp
        m = root_from_sig(idx_leaf, sig_ots, auth, m, seed, j, idx_tree)
    return m == root


def encode(h, r, idx, layers) -> bytes:
    """RFC 8391 §4.2.3 signature encoding: idx_sig (ceil(h/8) bytes) || r || d x (sig_ots || auth)."""
    out = to_byte(idx, (h + 7) // 8) + r
    for sig_ots, auth in layers:
        out += b"".join(sig_ots) + b"".join(auth)
    return out


def hx(b: bytes) -> str:
    return "0x" + b.hex()


# (h, d): a tiny non-standard set for fast fuzzing, then four of RFC 8391's eight
# XMSS^MT-SHA2 sets — the shortest per-layer trees (h/d = 5) at every total height,
# which reaches tree addresses up to 2^55, and the h/d = 10 set XMSSMT-SHA2_20/2_256.
SETS = ((4, 2), (20, 2), (20, 4), (40, 8), (60, 12))


def main():
    out_dir = os.path.join(os.path.dirname(__file__), "..", "test", "vectors")
    os.makedirs(out_dir, exist_ok=True)
    for h, d in SETS:
        key = Key(h, d, b"%d/%d" % (h, d))
        top = (1 << h) - 1
        vectors = []
        for idx in (0, 1, top, (top * 2) // 3):
            msg = sha(b"xmssmt/msg/%d/%d/%d" % (h, d, idx))
            r, layers = key.sign(msg, idx)
            assert verify(h, d, msg, idx, r, layers, key.root, key.seed)
            assert not verify(h, d, sha(b"x"), idx, r, layers, key.root, key.seed)
            vectors.append({
                "idx": hex(idx),
                "msg": hx(msg),
                "r": hx(r),
                "layers": [{"wotsSig": [hx(s) for s in o], "auth": [hx(a) for a in au]} for o, au in layers],
                "encoded": hx(encode(h, r, idx, layers)),
            })
        with open(os.path.join(out_dir, f"xmssmt_h{h}_d{d}.json"), "w") as f:
            json.dump({"h": h, "d": d, "seed": hx(key.seed), "root": hx(key.root), "vectors": vectors}, f, indent=1)
        print(f"h={h} d={d}: root={hx(key.root)} ({len(vectors)} vectors, {len(key._trees)} trees built)", flush=True)


if __name__ == "__main__":
    sys.exit(main())
