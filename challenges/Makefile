# Makefile for the heapnote challenges (fully local, no Docker).
#
# Two pinned glibc runtimes live next to this Makefile:
#   glibc-2.27/   libc-2.27.so + ld-2.27.so (+ libc.so.6 symlink)  -> C1-C3
#   glibc-2.35/   libc-2.35.so + ld-2.35.so (+ libc.so.6 symlink)  -> C4
# plus a linkable 2.27 sysroot at sysroot-2.27/ (crt + libc.so script + headers).
#
# Run `make setup` ONCE to fetch the .deb packages from the Ubuntu archive and
# build those dirs (see setup.sh). Then `make all` builds + patches both
# binaries. Swapping which libc a binary runs against is exactly what C4 vs
# C1-C3 demonstrates, so this layout is itself part of the teaching.
#
# Targets:
#   make setup    fetch + assemble glibc-2.27 glibc-2.35 sysroot-2.27
#   make all      heapnote (2.27) + heapnote_235 (2.35)
#   make heapnote      build only the 2.27 target
#   make heapnote_235  build only the 2.35 target
#   make clean
#
# Requires: gcc, patchelf, curl, dpkg. (pwntools/one_gadget for the exploits.)

CC       ?= gcc
PATCHELF ?= patchelf
CFLAGS   ?= -g -O0 -Wall

GLIBC227   = glibc-2.27
GLIBC235   = glibc-2.35
SYSROOT227 = sysroot-2.27

# gcc's own crtbegin/crtend are glibc-version-independent; pull them from the
# host compiler. crt1/crti/crtn come from the 2.27 sysroot so the binary only
# needs __libc_start_main@@GLIBC_2.2.5 (NOT the host's GLIBC_2.34 variant).
CRTBEGIN = $(shell $(CC) -print-file-name=crtbegin.o)
CRTEND   = $(shell $(CC) -print-file-name=crtend.o)

.PHONY: all clean setup

all: heapnote heapnote_235

# One-time: fetch pinned .debs and assemble the runtimes + sysroot.
setup:
	@./setup.sh

# --- 2.27 target -------------------------------------------------------------
# Link against the 2.27 sysroot: -nostdlib + explicit 2.27 crt + --sysroot so
# the libc.so linker script (with its absolute /lib/... paths) resolves under
# the sysroot. Interpreter + rpath are baked in at link time (no patchelf).
heapnote: heapnote.c $(SYSROOT227)/landmark $(GLIBC227)/libc.so.6
	$(CC) -nostdlib -no-pie $(CFLAGS) \
	  $(SYSROOT227)/usr/lib/x86_64-linux-gnu/crt1.o \
	  $(SYSROOT227)/usr/lib/x86_64-linux-gnu/crti.o \
	  $(CRTBEGIN) \
	  heapnote.c \
	  $(CRTEND) \
	  $(SYSROOT227)/usr/lib/x86_64-linux-gnu/crtn.o \
	  -o $@ \
	  --sysroot=$(SYSROOT227) \
	  -L$(SYSROOT227)/usr/lib/x86_64-linux-gnu \
	  -lc -lgcc \
	  -Wl,-z,lazy \
	  -Wl,--dynamic-linker=./$(GLIBC227)/ld-2.27.so \
	  -Wl,-rpath,./$(GLIBC227)
	@echo "[+] heapnote linked for glibc 2.27"

# --- 2.35 target ------------------------------------------------------------
# Host crt already matches 2.35 (host is glibc 2.35), so a normal compile then
# patchelf to the pinned 2.35 loader + rpath is enough.
heapnote_235: heapnote.c $(GLIBC235)/libc.so.6
	$(CC) -no-pie -z lazy $(CFLAGS) -o $@ heapnote.c
	$(PATCHELF) --set-interpreter ./$(GLIBC235)/ld-2.35.so --set-rpath ./$(GLIBC235) $@
	@echo "[+] heapnote_235 patched for glibc 2.35"

clean:
	rm -f heapnote heapnote_235