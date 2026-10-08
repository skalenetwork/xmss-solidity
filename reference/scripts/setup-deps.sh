#!/bin/sh
# Fetch the two libraries reference/ builds against into reference/lib/ (gitignored),
# each at the exact commit FermionWallet built the key registry and pre-approval engine
# against. They are not git submodules, so `forge install skalenetwork/xmss-solidity`
# and `git clone --recursive` pull only forge-std; only the `reference` Foundry profile
# needs these. Idempotent: a library already at its pinned commit is left alone.
#
# Usage: reference/scripts/setup-deps.sh    (then: FOUNDRY_PROFILE=reference forge test)
set -eu
LIB="$(cd "$(dirname "$0")/.." && pwd)/lib"

fetch() { # <dir> <url> <commit>
  dir="$LIB/$1"
  if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null || true)" = "$3" ] && [ -z "$(git -C "$dir" status --porcelain)" ]; then
    echo "$1: at $3"
    return
  fi
  rm -rf "$dir"
  mkdir -p "$dir"
  git -C "$dir" init -q
  git -C "$dir" fetch -q --depth 1 "$2" "$3"
  git -C "$dir" -c advice.detachedHead=false checkout -q FETCH_HEAD
  [ "$(git -C "$dir" rev-parse HEAD)" = "$3" ] || { echo "$1: fetched the wrong commit" >&2; exit 1; }
  echo "$1: fetched $3"
}

fetch openzeppelin-contracts https://github.com/OpenZeppelin/openzeppelin-contracts acd4ff74de833399287ed6b31b4debf6b2b35527
fetch safe-smart-account https://github.com/safe-global/safe-smart-account dc437e8fba8b4805d76bcbd1c668c9fd3d1e83be
