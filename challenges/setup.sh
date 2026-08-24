#!/usr/bin/env bash
# setup.sh — one-time local setup of the pinned glibc runtimes + debug
# symbols for the heapnote challenges. No Docker, no glibc.all.in.one repo:
# we fetch the exact Ubuntu .deb packages directly from the Ubuntu archive
# (what `apt download` does) and extract them with `dpkg -x`.
#
# Produces:
#   glibc-2.27/   runtime libc-2.27.so + ld-2.27.so (+ libc.so.6 symlink)  -> C1-C3
#   glibc-2.35/   runtime libc-2.35.so + ld-2.35.so (+ libc.so.6 symlink)  -> C4
#   sysroot-2.27/ a linkable 2.27 sysroot (crt + libc.so script + headers)
#                 so heapnote can be compiled against 2.27's startup objects
#                 (avoids the host's GLIBC_2.34 __libc_start_main).
#   dbg-2.27/     debug symbols (.build-id/.debug) for the pinned 2.27 libc
#   dbg-2.35/     debug symbols for the pinned 2.35 libc
#
# The dbg-*/ dirs let pwndbg resolve `main_arena` / `heap` from real symbols
# instead of heuristics (the shipped libcs are stripped):
#   pwndbg> set debug-file-directory dbg-2.27/usr/lib/debug
#   pwndbg> run          # restart so the libc's debug symbols attach
#   pwndbg> heap         # works (break AFTER the first malloc)
#
# Re-running is safe: dirs with a matching landmark are kept, stale ones
# (wrong build) are (re)built.
#
# Requirements: bash, curl, dpkg, gcc (for --sysroot builds).

set -euo pipefail
cd "$(dirname "$0")"

CACHE=.libc-cache
mkdir -p "$CACHE"

# 2.27-3ubuntu1 (Ubuntu 18.04 GA). IMPORTANT: the ORIGINAL GA build, not the
# later 2.27-3ubuntu1.x patch levels, because Ubuntu BACKPORTED the tcache
# double-free key (the "free(): double free detected in tcache 2" check) into
# 2.27-3ubuntu1.2+ (e.g. 1.6). The GA build is clean vanilla 2.27 with NO
# tcache key, which C1's self-loop double-free relies on. We also fetch the
# matching libc6-dbg so pwndbg can resolve heap symbols.
GA227=2.27-3ubuntu1
LIBC227_DEB=$CACHE/libc6_${GA227}_amd64.deb
DEV227_DEB=$CACHE/libc6-dev_${GA227}_amd64.deb
DBG227_DEB=$CACHE/libc6-dbg_${GA227}_amd64.deb
SEC=https://security.ubuntu.com/ubuntu/pool/main/g/glibc

# 2.35-0ubuntu3.14 (Ubuntu 22.04 jammy, current safe-linking stretch libc).
V235=2.35-0ubuntu3.14
LIBC235_DEB=$CACHE/libc6_${V235}_amd64.deb
DBG235_DEB=$CACHE/libc6-dbg_${V235}_amd64.deb
ARC=https://archive.ubuntu.com/ubuntu/pool/main/g/glibc

fetch() { # url dest
  local url=$1 dest=$2
  if [[ -s "$dest" ]]; then echo "  [have] $(basename "$dest")"; return; fi
  echo "  [get ] $(basename "$dest")"
  curl -fsSL -o "$dest" "$url"
}

extract_done() { # marker-dir ; true if already populated
  [[ -s "$1/landmark" ]]
}

# --- 2.27 runtime + sysroot + debug symbols ---------------------------------
if [[ ! -s glibc-2.27/libc-2.27.so \
      || "$(cat sysroot-2.27/landmark 2>/dev/null || true)" != "$GA227" ]]; then
  echo "[*] fetching 2.27 debs (libc6 + libc6-dev + libc6-dbg, $GA227)"
  fetch "$SEC/libc6_${GA227}_amd64.deb"      "$LIBC227_DEB"
  fetch "$SEC/libc6-dev_${GA227}_amd64.deb"  "$DEV227_DEB"
  fetch "$SEC/libc6-dbg_${GA227}_amd64.deb"  "$DBG227_DEB"
  echo "[*] extracting 2.27"
  rm -rf .x227 .dev227 glibc-2.27 sysroot-2.27 dbg-2.27
  mkdir -p .x227 .dev227 glibc-2.27 \
           sysroot-2.27/lib/x86_64-linux-gnu \
           sysroot-2.27/usr/lib/x86_64-linux-gnu \
           sysroot-2.27/usr/include \
           dbg-2.27
  dpkg -x "$LIBC227_DEB" .x227
  dpkg -x "$DEV227_DEB"  .dev227
  dpkg -x "$DBG227_DEB"  dbg-2.27
  # runtime pinned libs
  cp -L .x227/lib/x86_64-linux-gnu/libc-2.27.so glibc-2.27/
  cp -L .x227/lib/x86_64-linux-gnu/ld-2.27.so   glibc-2.27/
  ln -sf libc-2.27.so glibc-2.27/libc.so.6
  # The 2.27 libc6-dbg deb ships the libc debug file at
  # usr/lib/debug/lib/x86_64-linux-gnu/libc-2.27.so but OMITS the matching
  # .build-id/<2hex>/<rest>.debug symlink (it only carries a stray 28c6aade
  # entry for a different build), so gdb's build-id auto-load silently fails
  # and pwndbg falls back to heuristics. Recreate the symlink from the
  # runtime libc's build-id -> the debug file.
  BID227=$(readelf -n glibc-2.27/libc-2.27.so 2>/dev/null | awk '/Build ID:/{print $3; exit}')
  if [[ -n "$BID227" \
        && ! -e "dbg-2.27/usr/lib/debug/.build-id/${BID227:0:2}/${BID227:2}.debug" ]]; then
    mkdir -p "dbg-2.27/usr/lib/debug/.build-id/${BID227:0:2}"
    ln -sf ../../lib/x86_64-linux-gnu/libc-2.27.so \
      "dbg-2.27/usr/lib/debug/.build-id/${BID227:0:2}/${BID227:2}.debug"
  fi
  # sysroot: runtime libs
  cp -L .x227/lib/x86_64-linux-gnu/libc-2.27.so sysroot-2.27/lib/x86_64-linux-gnu/
  cp -L .x227/lib/x86_64-linux-gnu/ld-2.27.so   sysroot-2.27/lib/x86_64-linux-gnu/
  ln -sf libc-2.27.so       sysroot-2.27/lib/x86_64-linux-gnu/libc.so.6
  ln -sf ld-2.27.so         sysroot-2.27/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
  # sysroot: crt + linker script + nonshared + headers
  cp .dev227/usr/lib/x86_64-linux-gnu/crt1.o          sysroot-2.27/usr/lib/x86_64-linux-gnu/
  cp .dev227/usr/lib/x86_64-linux-gnu/Scrt1.o         sysroot-2.27/usr/lib/x86_64-linux-gnu/
  cp .dev227/usr/lib/x86_64-linux-gnu/crti.o           sysroot-2.27/usr/lib/x86_64-linux-gnu/
  cp .dev227/usr/lib/x86_64-linux-gnu/crtn.o          sysroot-2.27/usr/lib/x86_64-linux-gnu/
  cp .dev227/usr/lib/x86_64-linux-gnu/libc.so         sysroot-2.27/usr/lib/x86_64-linux-gnu/
  cp .dev227/usr/lib/x86_64-linux-gnu/libc_nonshared.a sysroot-2.27/usr/lib/x86_64-linux-gnu/
  cp -a .dev227/usr/include/. sysroot-2.27/usr/include/
  # debug symbols land at dbg-2.27/usr/lib/debug/.build-id/... (matched by build-id)
  echo "$GA227" > sysroot-2.27/landmark
  rm -rf .x227 .dev227
fi

# --- 2.35 runtime + debug symbols -------------------------------------------
if [[ ! -s glibc-2.35/libc-2.35.so \
      || "$(cat glibc-2.35/landmark 2>/dev/null || true)" != "$V235" ]]; then
  echo "[*] fetching 2.35 debs (libc6 + libc6-dbg, $V235)"
  fetch "$ARC/libc6_${V235}_amd64.deb"      "$LIBC235_DEB"
  fetch "$ARC/libc6-dbg_${V235}_amd64.deb"  "$DBG235_DEB"
  echo "[*] extracting 2.35"
  rm -rf .x235 glibc-2.35 dbg-2.35
  mkdir -p .x235 glibc-2.35 dbg-2.35
  dpkg -x "$LIBC235_DEB" .x235
  dpkg -x "$DBG235_DEB"  dbg-2.35
  cp -L .x235/lib/x86_64-linux-gnu/libc.so.6            glibc-2.35/libc-2.35.so
  cp -L .x235/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 glibc-2.35/ld-2.35.so
  ln -sf libc-2.35.so glibc-2.35/libc.so.6
  echo "$V235" > glibc-2.35/landmark
  rm -rf .x235
fi

echo "[+] done. glibc-2.27/ glibc-2.35/ sysroot-2.27/ dbg-2.27/ dbg-2.35/ ready."
echo "[+] pwndbg: set debug-file-directory dbg-2.27/usr/lib/debug  (or dbg-2.35/usr/lib/debug)"