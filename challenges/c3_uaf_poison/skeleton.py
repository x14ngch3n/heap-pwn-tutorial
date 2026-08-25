#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C3 - UAF-Edit tcache poisoning -> __free_hook -> system   (SKELETON)
====================================================================
Target : ./heapnote  (glibc 2.27, -no-PIE, partial RELRO)
Goal   : same shell as C2, but the POISONING VECTOR is a single
         use-after-free + Edit (NO double-free). This generalizes to
         glibc versions where double-free is detected (2.29+ tcache key).

This skeleton gives you: pwntools setup, ELF + libc load, process spawn,
the --demo pwndbg harness, and the menu helpers. YOU write the exploit.

TODO (fill in the three stages below):
  1. Leak libc base via the unsorted bin (same mechanic as C2).
  2. UAF-Edit poisoning (NOT a double-free):
       - Free TWO DISTINCT chunks into the same tcache bin (counts=2, but
         NO self-loop and NO double-free signature).
       - The HEAD's dangling data overlaps the freed chunk's fd. Use Edit
         on the head note to overwrite that fd with __free_hook.
       - malloc #1 returns the head chunk; malloc #2 returns __free_hook
         -> write system.
     Why is this "better" than C1's double-free? (no double-free at all ->
     no tcache-key trip on 2.29+.)
  3. Trigger: free a "/bin/sh" chunk -> system("/bin/sh").

Run:
    cd challenges && python3 c3_uaf_poison/skeleton.py
    cd challenges && python3 c3_uaf_poison/skeleton.py --demo
"""
from pwn import *
import sys

DEMO = "--demo" in sys.argv

context.binary = exe = ELF("./heapnote")
libc = ELF("./glibc-2.27/libc-2.27.so")
context.log_level = "info"

p = process("./heapnote")

# ---- live demo support (gdb/pwndbg + tmux) ----------------------------------
# In tmux, --demo attaches pwndbg in a right pane with `break menu`: the proc
# stops after every command, giving you a real prompt to run tcache/bins/heap.
# Inspect at each milestone, then `continue` in the gdb pane to advance.
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

# ===========================================================================
# TODO 1 - leak libc base via the unsorted bin (same as C2)
# ===========================================================================
# libc.address = ...
# log.success("libc base = %#x", libc.address)


# ===========================================================================
# TODO 2 - UAF-Edit poisoning (free two DISTINCT chunks, edit head's fd)
#          -> __free_hook = system
# ===========================================================================


# ===========================================================================
# TODO 3 - trigger: free a "/bin/sh" chunk -> system("/bin/sh")
# ===========================================================================


p.interactive()