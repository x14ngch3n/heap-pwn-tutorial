#!/usr/bin/env bash
# pack_handout.sh - build a student lab tree that EXCLUDES all solutions.
#
#   bash pack_handout.sh        -> ../handouts/lab/   (tree, ready to inspect)
#   bash pack_handout.sh --zip  -> ../handouts/lab/ + ../handouts/handout.zip
#
# Students get: handouts/guide.md (concepts + strategy, hint-level) + a
# lab/ tree with the binaries, libc, the challenge C source, flag.txt, and
# one skeleton.py per challenge. They do NOT get exp.py / solve.py (answer
# keys) or IDA / build-only artifacts.
#
# Run from challenges/:   bash pack_handout.sh
set -euo pipefail

SRC="$(pwd)"                       # .../challenges
ROOT="$(dirname "$SRC")"           # repo root
OUT="$ROOT/handouts/lab"           # generated lab tree (gitignored)
GUIDE="$ROOT/handouts/guide.md"    # source (tracked), zipped alongside lab
ZIP=0
[[ "${1:-}" == "--zip" ]] && ZIP=1

rm -rf "$OUT"
mkdir -p "$OUT"

# --- shared runtime (c1-c4 run against these from the lab/ cwd) -------------
cp "$SRC/heapnote"        "$OUT/"
cp "$SRC/heapnote_235"    "$OUT/"
cp "$SRC/heapnote.c"      "$OUT/"     # challenge source (read the bug in C)
cp "$SRC/flag.txt"        "$OUT/"     # local flag the exploit prints on shell
cp "$SRC/Makefile"        "$OUT/"
cp "$SRC/setup.sh"        "$OUT/"
cp -r "$SRC/glibc-2.27"   "$OUT/"
cp -r "$SRC/glibc-2.35"   "$OUT/"

# --- per-challenge skeletons (solutions exp.py/solve.py deliberately skipped)
for d in c1_double_free c2_unsorted_leak c3_uaf_poison c4_safe_linking; do
  mkdir -p "$OUT/$d"
  cp "$SRC/$d/skeleton.py" "$OUT/$d/"
done

# --- baby_talk: self-contained (own binary + libc + ld + flag) --------------
mkdir -p "$OUT/baby_talk"
cp "$SRC/baby_talk/binary"               "$OUT/baby_talk/"
cp "$SRC/baby_talk/libc.so.6"            "$OUT/baby_talk/"
cp "$SRC/baby_talk/ld-linux-x86-64.so.2" "$OUT/baby_talk/"
cp "$SRC/baby_talk/flag.txt"             "$OUT/baby_talk/"
cp "$SRC/baby_talk/fetch.sh"             "$OUT/baby_talk/"
cp "$SRC/baby_talk/skeleton.py"          "$OUT/baby_talk/"

# --- student lab README (generated so it always matches the packed tree) ----
cat > "$OUT/README.md" <<'README'
# heap pwn - student lab

Five challenges, easiest to hardest. Each `skeleton.py` gives you the
pwntools setup + menu helpers + a `--demo` pwndbg harness; the exploit
logic is left as `TODO` blocks for you to fill in. Read `../guide.md`
(or the zip's top-level `guide.md`) for the concepts and strategy.

## Layout

    heapnote, heapnote_235   - the two challenge binaries (c1-c4 use these)
    heapnote.c               - their C source (read the bug here)
    glibc-2.27/, glibc-2.35/ - the pinned libcs (already fetched, no setup needed)
    flag.txt                 - local flag your exploit prints once it shells
    c1_double_free/skeleton.py
    c2_unsorted_leak/skeleton.py
    c3_uaf_poison/skeleton.py
    c4_safe_linking/skeleton.py
    baby_talk/               - self-contained: own binary + libc + ld + flag

## How to work

    cd lab
    python3 c1_double_free/skeleton.py          # run your exploit
    python3 c1_double_free/skeleton.py --demo   # live pwndbg in a tmux split

With `--demo`, run inside tmux: pwndbg attaches in a right pane and stops
after every menu command so you can inspect the heap (`tcache`, `bins`,
`vis_heap_chunks`, `got`) between steps, then `continue` to advance.

## The chain (each builds on the last)

- C1 double-free  : tcache self-loop -> overwrite free@GOT with &win -> shell
- C2 unsorted leak: libc leak via unsorted bin -> __free_hook=system -> shell
- C3 UAF-Edit     : same shell, poison via ONE free + Edit (no double-free)
- C4 safe-linking : 2.35 PROTECT_PTR bypass -> GOT overwrite -> shell (stretch)
- baby_talk       : strtok null-write overlap -> __free_hook -> shell (capstone)

Goal of each: pop a shell and `cat flag.txt`. See `guide.md` for the how.
README

# --- sanity: prove no answer keys leaked ------------------------------------
LEAKS=$(find "$OUT" -name exp.py -o -name solve.py -o -name '*.i64' \
                         -o -name '*.id0' -o -name '*.id1' -o -name '*.id2' \
                         -o -name '*.nam' -o -name '*.til' | wc -l)
if [[ "$LEAKS" -ne 0 ]]; then
  echo "FATAL: $LEAKS answer-key / IDA files leaked into lab:" >&2
  find "$OUT" -name exp.py -o -name solve.py -o -name '*.i64' \
             -o -name '*.id0' -o -name '*.id1' -o -name '*.id2' \
             -o -name '*.nam' -o -name '*.til' >&2
  exit 1
fi

echo "lab tree built at $OUT"
echo "--- contents ---"
( cd "$OUT" && find . -type f | sort )

if [[ "$ZIP" -eq 1 ]]; then
  if [[ ! -f "$GUIDE" ]]; then
    echo "WARN: $GUIDE missing -- zipping lab only (no guide.md)" >&2
    ( cd "$ROOT" && rm -f handouts/handout.zip && zip -qr handouts/handout.zip handouts/lab )
  else
    ( cd "$ROOT" && rm -f handouts/handout.zip \
       && zip -qr handouts/handout.zip handouts/guide.md handouts/lab )
  fi
  echo "--- zip ---"
  echo "$ROOT/handouts/handout.zip  ($(du -h "$ROOT/handouts/handout.zip" | cut -f1))  (guide.md + lab/)"
fi