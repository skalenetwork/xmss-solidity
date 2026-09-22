#!/bin/sh
# Cross-check the test vectors against the RFC authors' C implementation
# (github.com/XMSS/xmss-reference): it must accept every h = 10 and h = 20
# signature in test/vectors and reject each one with a tampered message.
# The vectors come from py/xmss_ref.py, written for this project; this is the
# check against code this project did not write. Needs gcc and OpenSSL headers.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
REF_COMMIT=171ccbd26f098542a67eb5d2b128281c80bd71a6
WORK=${1:-$(mktemp -d)}
if [ ! -x "$WORK/xmss-reference/ui/xmss_open" ]; then
  git clone -q https://github.com/XMSS/xmss-reference "$WORK/xmss-reference"
  git -C "$WORK/xmss-reference" checkout -q "$REF_COMMIT"
  make -C "$WORK/xmss-reference" ui/xmss_open >/dev/null
fi
python3 "$HERE/crosscheck_reference.py" "$HERE/../test/vectors" "$WORK"
ok=0; total=0
for height in 10 20; do for i in 0 1 2 3; do
  total=$((total + 2))
  "$WORK/xmss-reference/ui/xmss_open" "$WORK/pk_h$height.bin" "$WORK/sm_h${height}_$i.bin" >/dev/null 2>&1 && ok=$((ok + 1)) || echo "REJECTED genuine h=$height vector $i"
  "$WORK/xmss-reference/ui/xmss_open" "$WORK/pk_h$height.bin" "$WORK/sm_h${height}_${i}_tampered.bin" >/dev/null 2>&1 && echo "ACCEPTED tampered h=$height vector $i" || ok=$((ok + 1))
done; done
echo "xmss-reference cross-check: $ok/$total as expected"
[ "$ok" = "$total" ]
