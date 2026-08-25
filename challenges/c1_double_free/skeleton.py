#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C1 - tcache double-free -> GOT overwrite -> win()   (SKELETON)
=============================================================
Target : ./heapnote  (glibc 2.27, -no-PIE, partial RELRO)
Goal   : overwrite free@GOT with &win, then call free -> shell.
Leak   : NONE (no-PIE; every address is a fixed binary address).

This skeleton gives you: pwntools setup, the ELF load, process spawn,
the --demo pwndbg harness, and the menu helpers. YOU write the exploit.

TODO (fill in the three stages below):
  1. Double-free ONE chunk so the tcache list becomes a self-loop A->A
     (counts=2). Why is this allowed on 2.27? (think: tcache key)
  2. 3-malloc rule:
       malloc #1 returns A -> edit A's data (= A->fd) to free@GOT
       malloc #2 returns A again (drains the self-loop); head = free@GOT
       malloc #3 returns free@GOT -> write &win there
     Hint: heapnote's add() mallocs TWO chunks per note (a 0x20 note_t
     struct + your data buffer). Pick a data size whose chunk bin DIFFERS
     from 0x20, or the struct malloc will eat your double-freed chunk.
  3. Trigger: free any still-live note -> hijacked free@GOT -> win() ->
     system("/bin/sh"). (del does NOT null the pointer, so the freed
     note's data pointer is still valid to free again.)

Run (from the handout's challenges/ dir):
    python3 c1_double_free/skeleton.py
    python3 c1_double_free/skeleton.py --demo
"""
from pwn import *
import sys

DEMO = "--demo" in sys.argv

context.binary = exe = ELF("./heapnote")
context.log_level = "info"

p = process("./heapnote")

# ---- live demo support (gdb/pwndbg + tmux) ----------------------------------
# In tmux, --demo attaches pwndbg in a right pane with `break menu`: the proc
# stops after every command, giving you a real prompt to run tcache/got/heap.
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

# ---- static (no-PIE) targets ------------------------------------------------
free_got = exe.got["free"]          # writable GOT entry (partial RELRO)
win_addr = exe.symbols["win"]       # system("/bin/sh")
log.info("free@GOT = %#x  |  win() = %#x", free_got, win_addr)

# ===========================================================================
# TODO 1 - double-free: make the tcache list A->A (self-loop), counts=2
# ===========================================================================


# ===========================================================================
# TODO 2 - 3-malloc rule -> overwrite free@GOT with &win
# ===========================================================================


# ===========================================================================
# TODO 3 - trigger free() -> win() -> shell
# ===========================================================================


p.interactive()