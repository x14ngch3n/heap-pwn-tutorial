#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
baby_talk (DiceCTF 2024) - strtok overlap -> tcache poison -> __free_hook   (SKELETON)
======================================================================================
Target : ./binary  (glibc 2.27, Full RELRO, PIE)
Goal   : leak heap + libc, build a chunk overlap via strtok's null write,
         poison __free_hook with system, free "/bin/sh" -> shell.

This skeleton gives you: pwntools setup, ELF + libc load, process spawn,
the --demo pwndbg harness, and the three menu helpers (str / tok / del).
YOU write the exploit.

The three commands
------------------
  str(size, data) : read(0, ptr, size) -- NO null terminator appended.
  tok(idx, delim) : strtok(ptr, delim) -- scans to \0 with NO length bound.
  del(idx)        : free(ptr) and NULLs the pointer (NO UAF / no double-free).

The bug
-------
str writes size bytes with no trailing \0. tok/strtok then scans forward
until it hits a \0, ignoring the chunk boundary -> it can walk into the
NEXT chunk's header. When strtok finds the delimiter it writes a \0 over
it -- if that byte is the low byte of the next chunk's size field, the
size changes (e.g. 0x101 -> 0x100) and PREV_INUSE is cleared, enabling a
backward consolidation that produces an OVERLAP with a live tcache chunk.

TODO (fill in the stages below):
  1. Leak heap base + libc base. malloc never zeroes reused memory, so a
     freed tcache chunk's slot keeps a RESIDUAL fd. Use tok (strtok) to
     read those residual bytes back out (no show/UAF command exists).
     Hint: prime one size class, free into it, re-alloc, then tok with a
     delimiter that stops right where the residual fd sits.
  2. Build the overlap: sculpt a fake prev chunk, then use tok's null
     write to clear PREV_INUSE on a neighbour -> free it -> backward
     consolidation -> one chunk now spans a live tcache entry.
  3. Through the overlap, forge a fake tcache chunk whose fd points at
     __free_hook. Allocate to pop __free_hook, write system. Allocate a
     "/bin/sh" chunk and free it -> system("/bin/sh").

Run (sets its own cwd -- runs from anywhere):
    python3 baby_talk/skeleton.py
    python3 baby_talk/skeleton.py --demo
"""
from pathlib import Path
from pwn import *
import sys

DEMO = "--demo" in sys.argv

ROOT = Path(__file__).resolve().parent
context.binary = str(ROOT / "binary")
context.log_level = "info"

libc = ELF(str(ROOT / "libc.so.6"), checksec=False)

# cwd=ROOT: the binary's INTERP and RUNPATH are both "." (relative), so the
# inferior must start with baby_talk/ as its CWD for ld-linux + libc.so.6 to
# resolve.
io = process(str(ROOT / "binary"), cwd=str(ROOT))


# ---- live demo support (gdb/pwndbg + tmux) ----------------------------------
# In tmux, --demo attaches pwndbg in a right pane with `break print_menu`: the
# proc stops after every command, giving you a real prompt to run
# vis_heap_chunks/bins/tcache. Inspect at each milestone, then `continue` in
# the gdb pane to advance.
def demo_hint(msg: str):
    if DEMO:
        log.info("DEMO | %s", msg)

if DEMO:
    context.terminal = ["tmux", "splitw", "-h", "-p", "55"]
    gdb.attach(io, gdbscript="break print_menu\ncontinue\n")
    demo_hint("gdb attached (right pane). Proc stops after each command; inspect, then `continue` to advance.")

# ---- menu helpers -----------------------------------------------------------
def do_str(io, size: int, data: bytes) -> int:
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"size? ", str(size).encode())
    io.sendafter(b"str? ", data)
    io.recvuntil(b"stored at ")
    return int(io.recvuntil(b"!", drop=True).decode())

def do_tok(io, idx: int, delim: bytes) -> list:
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"idx? ", str(idx).encode())
    io.sendlineafter(b"delim? ", delim)
    return io.recvuntil(b"\n1. str", drop=True).splitlines()

def do_del(io, idx: int):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"idx? ", str(idx).encode())

# ===========================================================================
# TODO 1 - leak heap base + libc base via residual fd (read with tok)
# ===========================================================================
# heap_base = ...
# libc.address = ...
# log.success("heap base = %#x", heap_base)
# log.success("libc base = %#x", libc.address)


# ===========================================================================
# TODO 2 - build the overlap (strtok null write -> clear PREV_INUSE ->
#          backward consolidation -> overlap a live tcache chunk)
# ===========================================================================


# ===========================================================================
# TODO 3 - poison __free_hook with system via the overlap, free "/bin/sh"
# ===========================================================================


io.interactive()