#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C4 (stretch) - safe-linking (PROTECT_PTR) bypass -> GOT overwrite   (SKELETON)
===============================================================================
Target : ./heapnote_235  (glibc 2.35, -no-PIE, partial RELRO)
Goal   : defeat safe-linking to tcache-poison on 2.35, then GOT-overwrite
         puts@GOT with &win -> next menu() puts() -> win() -> shell.

This skeleton gives you: pwntools setup, ELF load, process spawn,
the --demo pwndbg harness, the menu helpers, and the PROTECT_PTR helper.
YOU write the exploit.

Background: glibc 2.32+ safe-linking
------------------------------------
The tcache fd is no longer the raw next pointer but
        stored_fd = PROTECT_PTR(&fd_slot, next) = (&fd_slot >> 12) XOR next
where &fd_slot is the address of the fd field (the chunk's user data).
To poison fd to point at a target T you must write (&fd_slot >> 12) XOR T,
which requires knowing &fd_slot >> 12 -- i.e. the heap PAGE.

TODO (fill in the stages below):
  1. heap-page leak: free a tcache chunk as the ONLY entry in its bin ->
     its real next is NULL -> stored_fd = (&fd>>12) XOR 0 = &fd>>12.
     UAF-read that stored fd -> you have the heap page (the >>12 key).
  2. Forge fd = PROTECT_PTR(&fd, puts@GOT) -> tcache returns puts@GOT ->
     write &win -> the next menu() loop calls puts() -> win() -> shell.
     SUBTLETY: 2.34+ tcache_get() zeroes returned_ptr+8 (writes e->key=0),
     so the slot AFTER the one you overwrite also gets zeroed. Pick a GOT
     slot whose +8 neighbour is NOT used in the menu path. (win() must
     still reach a working system@GOT.)

Run (from the handout's challenges/ dir):
    python3 c4_safe_linking/skeleton.py
    python3 c4_safe_linking/skeleton.py --demo
NOTE: the prebuilt `heapnote_235` + `glibc-2.35/` ship in the handout -- no build.
"""
from pwn import *
import sys

DEMO = "--demo" in sys.argv

context.binary = exe = ELF("./heapnote_235")
context.log_level = "info"

p = process("./heapnote_235")

# ---- live demo support (gdb/pwndbg + tmux) ----------------------------------
# In tmux, --demo attaches pwndbg in a right pane with `break menu`: the proc
# stops after every command, giving you a real prompt to run bins/tcache/got.
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

# ---- safe-linking helper ----------------------------------------------------
def protect_ptr(fd_slot_addr: int, target: int) -> int:
    return (fd_slot_addr >> 12) ^ target

# ---- static (no-PIE) targets ------------------------------------------------
win_addr = exe.symbols["win"]
log.info("win() = %#x", win_addr)

# ===========================================================================
# TODO 1 - heap-page leak via a singly-freed tcache chunk (stored fd = &fd>>12)
# ===========================================================================
# heap_page = ...
# log.success("heap page (>>12) = %#x", heap_page)


# ===========================================================================
# TODO 2 - forge fd = PROTECT_PTR(&fd, puts@GOT) -> overwrite puts@GOT with
#          &win -> next menu() puts() -> win() -> shell
#          (mind tcache_get zeroing returned_ptr+8)
# ===========================================================================


p.interactive()