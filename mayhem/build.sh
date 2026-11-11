#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# kvm-guest-drivers-windows is Windows kernel-driver source. The pieces below are compiled unmodified on
# Linux against stand-in headers in mayhem/shim (force-included, never edits to upstream files).
B=/tmp/kvm-build
rm -rf "$B" && mkdir -p "$B"
# VirtIORing*.c include "windows\virtio_ring_allocation.h" (a literal backslash on Linux): serve it from a generated shim.
mkdir -p "$B/inc"
printf '#include "windows/virtio_ring_allocation.h"\n' > "$B/inc/windows\\virtio_ring_allocation.h"
INC="-I$B/inc -I$SRC/mayhem/shim -I$SRC/VirtIO -I$SRC/NetKVM/Common -I$SRC/NetKVM"
CXXSHIM="-include $SRC/mayhem/shim/ndis56common_shim.h"
CSHIM="-include $SRC/mayhem/shim/ntddk.h"

# 1) Fuzz-build the libraries: NetKVM's sw_offload.cpp (packet parsing/checksums) and VirtIO's split+packed
#    rings. -fno-sanitize=alignment on sw_offload only: its _WIN64 checksum path does unaligned 32-bit loads
#    (benign on the x86 target); every other ASan/UBSan check stays halting.
FZ="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link -w"
$CXX -std=c++17 $FZ -fno-sanitize=alignment $CXXSHIM $INC -c "$SRC/NetKVM/Common/sw_offload.cpp" -o "$B/sw_offload.o"
$CC -std=gnu11 $FZ $CSHIM $INC -DMAYHEM_U32_LONG -c "$SRC/VirtIO/VirtIORing.c" -o "$B/VirtIORing.o"
$CC -std=gnu11 $FZ $CSHIM $INC -c "$SRC/VirtIO/VirtIORing-Packed.c" -o "$B/VirtIORing-Packed.o"
# The PCI transport files store vp_notify() (returns bool) as a void(*)(struct virtqueue *) notify callback, which is the
# same call on the Windows ABI (-fno-sanitize=function, -Wno-incompatible-function-pointer-types). Every other check stays on.
for f in VirtIOPCICommon VirtIOPCIModern VirtIOPCILegacy; do
  $CC -std=gnu11 $FZ -fno-sanitize=function -Wno-incompatible-function-pointer-types $CSHIM $INC -c "$SRC/VirtIO/$f.c" -o "$B/$f.o"
done
$CC -std=gnu11 $FZ $INC -c "$SRC/mayhem/shim/dbg_globals.c" -o "$B/dbg_globals.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"

# 2) Harnesses: libFuzzer binary + standalone reproducer each.
$CXX -std=c++17 $FZ -fno-sanitize=alignment $CXXSHIM $INC -c "$SRC/mayhem/netkvm_offload/netkvm_offload_fuzz.cpp" -o "$B/netkvm_offload_fuzz.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/netkvm_offload_fuzz.o" "$B/sw_offload.o" "$B/dbg_globals.o" "$B/lsan_off.o" -o /mayhem/netkvm_offload
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/netkvm_offload_fuzz.o" "$B/sw_offload.o" "$B/dbg_globals.o" "$B/lsan_off.o" "$B/standalone_main.o" -o /mayhem/netkvm_offload-standalone

$CC -std=gnu11 $FZ $CSHIM $INC -c "$SRC/mayhem/virtio_ring/virtio_ring_fuzz.c" -o "$B/virtio_ring_fuzz.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/virtio_ring_fuzz.o" "$B/VirtIORing.o" "$B/VirtIORing-Packed.o" "$B/dbg_globals.o" "$B/lsan_off.o" -o /mayhem/virtio_ring
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/virtio_ring_fuzz.o" "$B/VirtIORing.o" "$B/VirtIORing-Packed.o" "$B/dbg_globals.o" "$B/lsan_off.o" "$B/standalone_main.o" -o /mayhem/virtio_ring-standalone

$CC -std=gnu11 $FZ $CSHIM $INC -c "$SRC/mayhem/virtio_pci/virtio_pci_fuzz.c" -o "$B/virtio_pci_fuzz.o"
PCI_OBJS="$B/virtio_pci_fuzz.o $B/VirtIOPCICommon.o $B/VirtIOPCIModern.o $B/VirtIOPCILegacy.o $B/VirtIORing.o $B/VirtIORing-Packed.o $B/dbg_globals.o $B/lsan_off.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE $PCI_OBJS -o /mayhem/virtio_pci
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $PCI_OBJS "$B/standalone_main.o" -o /mayhem/virtio_pci-standalone

# vioinput's HID descriptor builder (Hid.c + the HID*Probe class files), built against WDF/HID stand-ins in mayhem/shim_input
# . The harness replaces VirtIOWdfDeviceGet/Set with a fake config space.
# The *.tmh files #included under EVENT_TRACING are WPP-generated; empty stand-ins are generated into $B/inc (git ignores *.tmh).
for f in Array Hid HidMouse HidJoystick HidTablet HidKeyboard HidConsumer KeyMap; do printf '#include "wpp_stub.h"\n' > "$B/inc/$f.tmh"; done
HI="-I$B/inc -I$SRC/mayhem/shim_input -I$SRC/mayhem/shim -I$SRC/VirtIO -I$SRC/VirtIO/WDF -I$SRC/vioinput/sys"
VI_SRCS="Array Hid HidMouse HidJoystick HidTablet HidKeyboard HidConsumer KeyMap"
VI_OBJS=""
for f in $VI_SRCS; do
  $CC -std=gnu11 $FZ -fms-extensions $CSHIM $HI -c "$SRC/vioinput/sys/$f.c" -o "$B/vi_$f.o"
  VI_OBJS="$VI_OBJS $B/vi_$f.o"
done
$CC -std=gnu11 $FZ -fms-extensions $CSHIM $HI -c "$SRC/mayhem/vioinput_hid/vioinput_hid_fuzz.c" -o "$B/vioinput_hid_fuzz.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/vioinput_hid_fuzz.o" $VI_OBJS "$B/dbg_globals.o" "$B/lsan_off.o" -o /mayhem/vioinput_hid
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/vioinput_hid_fuzz.o" $VI_OBJS "$B/dbg_globals.o" "$B/lsan_off.o" "$B/standalone_main.o" -o /mayhem/vioinput_hid-standalone

# viogpu's EDID helpers (edid.cpp), built against the same WDF/WDDM stand-ins (viogpu.h pulls the miniport headers in).
GI="-I$SRC/mayhem/shim_input -I$SRC/mayhem/shim -I$SRC/VirtIO -I$SRC/viogpu/common -I$SRC/viogpu/shared -I$SRC/viogpu/viogpudo"
$CXX -std=c++17 $FZ -fms-extensions $CSHIM $GI -c "$SRC/viogpu/common/edid.cpp" -o "$B/edid.o"
$CXX -std=c++17 $FZ -fms-extensions $CSHIM $GI -c "$SRC/mayhem/viogpu_edid/viogpu_edid_fuzz.cpp" -o "$B/viogpu_edid_fuzz.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/viogpu_edid_fuzz.o" "$B/edid.o" "$B/dbg_globals.o" "$B/lsan_off.o" -o /mayhem/viogpu_edid
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$B/viogpu_edid_fuzz.o" "$B/edid.o" "$B/dbg_globals.o" "$B/lsan_off.o" "$B/standalone_main.o" -o /mayhem/viogpu_edid-standalone

# 3) Known-answer tests with NORMAL flags (no sanitizers), for mayhem/test.sh.
NF="-O1 -w $COVERAGE_FLAGS"
$CXX -std=c++17 $NF $CXXSHIM $INC -c "$SRC/NetKVM/Common/sw_offload.cpp" -o "$B/t_sw_offload.o"
$CC -std=gnu11 $NF $INC -c "$SRC/mayhem/shim/dbg_globals.c" -o "$B/t_dbg_globals.o"
$CXX -std=c++17 $NF $CXXSHIM $INC "$SRC/mayhem/kat/kat_offload.cpp" "$B/t_sw_offload.o" "$B/t_dbg_globals.o" -o /mayhem/kat_offload
$CC -std=gnu11 $NF $CSHIM $INC -DMAYHEM_U32_LONG -c "$SRC/VirtIO/VirtIORing.c" -o "$B/t_VirtIORing.o"
$CC -std=gnu11 $NF $CSHIM $INC -c "$SRC/VirtIO/VirtIORing-Packed.c" -o "$B/t_VirtIORing-Packed.o"
$CC -std=gnu11 $NF $CSHIM $INC "$SRC/mayhem/kat/kat_ring.c" "$B/t_VirtIORing.o" "$B/t_VirtIORing-Packed.o" "$B/t_dbg_globals.o" -o /mayhem/kat_ring
for f in VirtIOPCICommon VirtIOPCIModern VirtIOPCILegacy; do
  $CC -std=gnu11 $NF -Wno-incompatible-function-pointer-types $CSHIM $INC -c "$SRC/VirtIO/$f.c" -o "$B/t_$f.o"
done
$CC -std=gnu11 $NF $CSHIM $INC "$SRC/mayhem/kat/kat_pci.c" "$B/t_VirtIOPCICommon.o" "$B/t_VirtIOPCIModern.o" "$B/t_VirtIOPCILegacy.o" \
  "$B/t_VirtIORing.o" "$B/t_VirtIORing-Packed.o" "$B/t_dbg_globals.o" -o /mayhem/kat_pci
VI_TOBJS=""
for f in $VI_SRCS; do
  $CC -std=gnu11 $NF -fms-extensions $CSHIM $HI -c "$SRC/vioinput/sys/$f.c" -o "$B/t_vi_$f.o"
  VI_TOBJS="$VI_TOBJS $B/t_vi_$f.o"
done
$CC -std=gnu11 $NF -fms-extensions $CSHIM $HI "$SRC/mayhem/kat/kat_hid.c" $VI_TOBJS "$B/t_dbg_globals.o" -o /mayhem/kat_hid
$CXX -std=c++17 $NF -fms-extensions $CSHIM $GI -c "$SRC/viogpu/common/edid.cpp" -o "$B/t_edid.o"
$CXX -std=c++17 $NF -fms-extensions $CSHIM $GI "$SRC/mayhem/kat/kat_edid.cpp" "$B/t_edid.o" -o /mayhem/kat_edid
