#!/usr/bin/env python3
"""Guard the Halmos proof run against two silent failure modes.

1. Loop bound: Halmos unrolls loops up to --loop and proves properties of the
   unrolled program without failing when a loop is cut short. The bound must
   exceed the longest loop in the verifier (LEN = 67 WOTS+ chains).
2. Vacuity: a check whose vm.assume preconditions exclude (almost) every input
   passes on nothing. Halmos prints how many paths it explored; each check must
   reach at least the floor recorded from a known-good run (proof-paths.json).

Usage: check_proof_run.py <loop-bound> <halmos-output-file>
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
loop_bound = int(sys.argv[1])
out = open(sys.argv[2]).read()
out = re.sub(r"\x1b\[[0-9;]*m", "", out)

src = open(os.path.join(HERE, "..", "src", "XMSS.sol")).read()
LEN = int(re.search(r"uint256 internal constant LEN = (\d+);", src).group(1))
if loop_bound <= LEN:
    sys.exit(f"--loop {loop_bound} does not exceed LEN = {LEN}: Halmos would truncate the WOTS+ loop")

# The proof is of bytecode from one compiler configuration. PROOF.md records it; if
# foundry.toml moves on, the recorded claim must be updated in the same change.
toml = open(os.path.join(HERE, "..", "foundry.toml")).read()
pinned = re.search(r'solc_version\s*=\s*"([^"]+)"', toml).group(1)
proof_md = open(os.path.join(HERE, "..", "PROOF.md")).read()
if f"solc {pinned}" not in proof_md:
    sys.exit(f"foundry.toml pins solc {pinned} but PROOF.md does not state that version: re-run the proof and update PROOF.md")

# Under an uninterpreted hash, an inequality between hash outputs is unprovable (the
# solver may assume collisions). Lemmas must be equalities or rejections of inputs
# that never reach a hash; an assertNotEq on bytes32 in the proof file is a mistake.
proof_src = open(os.path.join(HERE, "..", "test", "proof", "XMSSEquivalence.t.sol")).read()
if re.search(r"assertNotEq\s*\(", proof_src):
    sys.exit("XMSSEquivalence.t.sol uses assertNotEq: hash-output inequalities cannot be proven under the SHA-256 abstraction")

floors = json.load(open(os.path.join(HERE, "proof-paths.json")))
seen = {}
for m in re.finditer(r"\[(PASS|FAIL|ERROR|TIMEOUT)\] (check_\w+)\(.*?\(paths: (\d+),", out):
    seen[m.group(2)] = (m.group(1), int(m.group(3)))

failed = []
# A solver that gave up on a path is reported by Halmos as a warning, not a failure,
# and the check can still print PASS. Treat any such warning as a rejected run.
for m in re.finditer(r"(?i)(unknown|timeout|NotConcreteError|Encountered|concretiz|symbolic [A-Z]+)[^\n]{0,160}", out):
    line = m.group(0)
    if "WARNING" in out[max(0, m.start() - 80):m.start()] or line.lower().startswith(("unknown", "timeout")):
        failed.append("solver/engine warning: " + line.strip())
for name, floor in floors.items():
    if name not in seen:
        failed.append(f"{name}: not run")
        continue
    status, paths = seen[name]
    if status != "PASS":
        failed.append(f"{name}: {status}")
    elif paths < floor:
        failed.append(f"{name}: explored {paths} paths, floor is {floor} (a precondition may now exclude most inputs)")
for name in seen:
    if name not in floors:
        failed.append(f"{name}: no path floor recorded in proof-paths.json; add one from a known-good run")
if failed:
    sys.exit("proof run rejected:\n  " + "\n  ".join(failed))
print(f"proof run ok: --loop {loop_bound} > LEN {LEN}; {len(floors)} checks passed at or above their path floors")
