#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C2 - unsorted bin libc leak -> __free_hook -> system   (SKELETON)
================================================================
Target : ./heapnote  (glibc 2.27, -no-PIE, partial RELRO)
Goal   : leak libc base, overwrite __free_hook with system, free a
         "/bin/sh" chunk -> system("/bin/sh").

This skeleton gives you: pwntools setup, ELF + libc load, process spawn,
the --demo pwndbg harness, and the menu helpers. YOU write the exploit.

TODO (fill in the three stages below):
  1. Leak libc base via the unsorted bin:
       - tcache only holds chunk sizes 0x20..0x410. A request >= 0x418
         makes a 0x420 chunk that tcache will NOT keep -> on free it lands
         in the UNSORTED BIN. Put a guard chunk after it so it won't merge
         into top.
       - A freed unsorted chunk's fd points at the bin head, whose "chunk"
         address is main_arena + 96 (0x60) on 2.27 x86-64.
       - main_arena = __malloc_hook + 0x10, so:
             libc_base = leak - (__malloc_hook + 0x10) - 96
       - UAF-read the fd with show() (del does not null the pointer).
     From libc_base, derive system, __free_hook, and the "/bin/sh" string.
  2. tcache poisoning (reuse C1's double-free 3-malloc) -> write system
     into __free_hook. (0x68 request -> 0x70 bin is a comfortable size.)
  3. Trigger: allocate a chunk whose data is "/bin/sh\x00" and free it ->
     __free_hook(ptr) -> system("/bin/sh").

Run (from the handout's challenges/ dir):
    python3 c2_unsorted_leak/skeleton.py
    python3 c2_unsorted_leak/skeleton.py --demo
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
# stops after every command, giving you a real prompt to run bins/tcache/heap.
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
# TODO 1 - leak libc base via the unsorted bin
# ===========================================================================
# libc.address = ...
# log.success("libc base = %#x", libc.address)


# ===========================================================================
# TODO 2 - tcache poisoning (double-free 3-malloc) -> __free_hook = system
# ===========================================================================


# ===========================================================================
# TODO 3 - trigger: free a "/bin/sh" chunk -> system("/bin/sh")
# ===========================================================================


p.interactive()