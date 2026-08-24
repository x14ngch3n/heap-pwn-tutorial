#!/usr/bin/env bash
# Fetch the shipped libc + loader for baby_talk (DiceCTF 2024).
# The binary is committed already (patchelf'd to ./ld + rpath .); the libc
# and ld are ~19 MB together and reproducible, so we fetch them on demand,
# matching the tutorial's "large reproducible artifacts not committed" rule.
set -euo pipefail
cd "$(dirname "$0")"

BASE=https://raw.githubusercontent.com/ZhangZhuoSJTU/ctf-collection/main/ctf-pwn/dicectf_2024_baby_talk

for f in libc.so.6 ld-linux-x86-64.so.2; do
  if [ ! -s "$f" ]; then
    echo "fetching $f"
    curl -sSL -o "$f" "$BASE/$f"
    chmod +x "$f"
  fi
done

# sanity: loader must resolve libc from this dir
./ld-linux-x86-64.so.2 --list ./binary | grep -q "libc.so.6 => ./libc.so.6" \
  && echo "OK: libc resolves locally" \
  || { echo "FAIL: libc did not resolve to ./libc.so.6"; exit 1; }