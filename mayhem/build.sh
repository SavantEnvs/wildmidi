#!/usr/bin/env bash
#
# wildmidi/mayhem/build.sh -- build (a) three sanitized libFuzzer harnesses over
# WildMIDI's music-file parsers + their standalone reproducers, and (b) a
# SEPARATE, clean, non-sanitized build of WildMIDI's own ctest suite plus the
# mayhem/kat/ known-answer probe that mayhem/test.sh runs as its oracle.
#
# WildMIDI is a software MIDI synthesizer library.  The bytes-eating surface is
# its per-format readers and converters, all under src/:
#   readers   (build a synth event stream): f_midi.c f_xmidi.c f_mus.c f_hmp.c
#                                          f_hmi.c f_smaf.c + internal_midi.c
#   converters(rewrite the file as an SMF): xmi2mid.c mus2mid.c hmp2mid.c
#                                          hmi2mid.c smaf2mid.c
# Targets (one per format family; see each harness's header comment):
#   fuzz_midi -- WildMidi_OpenBuffer(): the public buffer entry point, which
#                sniffs the format and dispatches to ALL SIX readers.
#   fuzz_xmi  -- _WM_xmi2midi():  the XMIDI -> SMF converter, called directly so
#                every mutated input reaches the chunk walker ungated.
#   fuzz_mus  -- _WM_mus2midi():  the DOOM MUS -> SMF converter, likewise.
#
# THE WildMidi_Init() CONFIG-FILE GOTCHA (the thing worth knowing about this
# repo).  WildMidi_OpenBuffer() returns NULL until WildMidi_Init() has
# succeeded, and Init normally loads a patch/config file (a .cfg listing GUS
# patch files) -- a filesystem dependency a harness must not have.  WildMIDI
# ships an escape hatch: the sentinel config name "@opl3" (WM_OPL3_CONFIG,
# include/synth.h).  Passing it makes _WM_Init() skip config loading entirely
# and populate the patch table from an embedded DMXOPL bank rendered by the
# built-in Nuked OPL3 emulator (src/wildmidi_lib.c:1781 ->
# src/synth.c:_WM_opl3_init_patches -- pure in-memory work).  So NO .cfg file is
# committed and no harness performs any file I/O; fuzz_xmi/fuzz_mus call the
# converters, which need no Init at all.  This build therefore needs WANT_SF2
# left ON only for the library's own sake, not for the harnesses.
#
# ZERO network access: WildMIDI's CMake build has no FetchContent/ExternalProject
# and no external dependencies once the player frontends are off (the audio
# backends -- ALSA/OSS/SDL/OpenAL/sndio -- are only probed when WANT_PLAYER or
# WANT_PLAYERSTATIC is on, CMakeLists.txt:243, and both are OFF here).  Only
# libm is needed.  So the air-gapped PATCH re-run (SPEC 6.5) needs no vendoring.
# Both cmake build dirs are reused in place, so re-running on an already-built
# tree is a near-no-op (idempotent).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) -- must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# The fuzzed LIBRARY must carry SanitizerCoverage, not just the harness TU:
# $LIB_FUZZING_ENGINE only instruments what it is linked into, and
# $SANITIZER_FLAGS carries no coverage flags -- without this the targets build,
# pass fuzz-smoke, and then record 0 edges in Mayhem.  Appended
# UNCONDITIONALLY, including for the empty (no-sanitizer) override.
case "$SANITIZER_FLAGS" in
  *fuzzer-no-link*) ;;                                                   # already present
  *) SANITIZER_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link" ;;
esac
# DWARF <= 3 (SPEC 6.2 item 10): clang-19's plain -g emits DWARF-5, and the base
# image's SANITIZER_FLAGS ends in a bare -g -- so pass these AFTER it (last wins).
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE STANDALONE_FUZZ_MAIN MAYHEM_JOBS
: "${SRC:=/mayhem}"
cd "$SRC"

TARGETS="fuzz_midi fuzz_xmi fuzz_mus"
HARNESS_DIR="$SRC/mayhem/harnesses"
FUZZ_BUILD="$SRC/cmake-build-fuzz"     # sanitized library (matches upstream .gitignore cmake-build*/)
TEST_BUILD="$SRC/cmake-build-test"     # clean oracle build: upstream ctest suite + the KAT probe

# ── 1) The WildMIDI library, WITH sanitizers + SanCov + DWARF3 ────────────────
# Static-only, player OFF (no ALSA/OSS/SDL/OpenAL), DevTest OFF, tests OFF: the
# fuzz build needs nothing but libWildMidi.a.
cmake -S "$SRC" -B "$FUZZ_BUILD" \
      -DCMAKE_C_COMPILER="$CC" \
      -DCMAKE_BUILD_TYPE=None \
      -DCMAKE_C_FLAGS="-O1 $SANITIZER_FLAGS $DEBUG_FLAGS" \
      -DBUILD_SHARED_LIBS=OFF \
      -DWANT_STATIC=ON \
      -DWANT_PLAYER=OFF \
      -DWANT_DEVTEST=OFF \
      -DBUILD_TESTING=OFF
cmake --build "$FUZZ_BUILD" --target libwildmidi-static -j "$MAYHEM_JOBS"

LIBWM_FUZZ="$FUZZ_BUILD/src/libWildMidi.a"
[ -f "$LIBWM_FUZZ" ] || { echo "FATAL: sanitized $LIBWM_FUZZ was not produced" >&2; exit 1; }

# ── 2) The standalone (non-fuzzer) run-once driver, compiled once as C ────────
# $STANDALONE_FUZZ_MAIN is a C file; -x c keeps its LLVMFuzzerTestOneInput
# reference unmangled.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c -x c "$STANDALONE_FUZZ_MAIN" \
    -o "$FUZZ_BUILD/standalone_main.o"

# ── 3) Each harness twice: libFuzzer target + standalone reproducer ───────────
INC="-I$SRC/include -I$FUZZ_BUILD/include"
for t in $TARGETS; do
  [ -f "$HARNESS_DIR/$t.c" ] || { echo "FATAL: missing $HARNESS_DIR/$t.c" >&2; exit 1; }

  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $INC \
      "$HARNESS_DIR/$t.c" $LIB_FUZZING_ENGINE "$LIBWM_FUZZ" -lm \
      -o "/mayhem/$t"

  # Standalone reproducer: one input file, one LLVMFuzzerTestOneInput call, no
  # libFuzzer runtime. A debugging artifact, NOT a Mayhem target.
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $INC \
      "$HARNESS_DIR/$t.c" "$FUZZ_BUILD/standalone_main.o" "$LIBWM_FUZZ" -lm \
      -o "/mayhem/$t-standalone"

  [ -x "/mayhem/$t" ] && [ -x "/mayhem/$t-standalone" ] \
    || { echo "FATAL: $t did not link" >&2; exit 1; }
  echo "built $t (+ standalone)"
done

# ── 4) Per-target dictionaries ───────────────────────────────────────────────
# The Mayhemfiles reference /mayhem/<target>.dict; a referenced-but-absent dict
# makes libFuzzer exit 1 at 0 edges, so every one MUST be copied into place.
for t in $TARGETS; do
  d="$SRC/mayhem/$t/$t.dict"
  [ -f "$d" ] || { echo "FATAL: missing dictionary $d (referenced by mayhem/Mayhemfile_$t)" >&2; exit 1; }
  cp -f "$d" "/mayhem/$t.dict"
  echo "copied dictionary /mayhem/$t.dict"
done

# ── 5) The ORACLE build: WildMIDI's own ctest suite + the KAT probe ──────────
# A SEPARATE build dir with the project's NORMAL flags -- NO sanitizers, NO
# -gdwarf-3 -- so mayhem/test.sh stays an honest functional oracle. Nothing here
# collides with step 1 (different directory).
cmake -S "$SRC" -B "$TEST_BUILD" \
      -DCMAKE_C_COMPILER="$CC" \
      -DBUILD_SHARED_LIBS=OFF \
      -DWANT_STATIC=ON \
      -DWANT_PLAYER=OFF \
      -DWANT_DEVTEST=OFF \
      -DBUILD_TESTING=ON
cmake --build "$TEST_BUILD" -j "$MAYHEM_JOBS"

# WildMIDI's registered ctest cases (test/CMakeLists.txt). ctest judges these by
# EXIT CODE only, which is why the KAT probe below exists -- see mayhem/test.sh.
for b in test_tokenize test_smaf_sequ test_ma7_voice test_smaf_mtsp test_smaf_7f23; do
  [ -x "$TEST_BUILD/test/$b" ] \
    || { echo "FATAL: upstream test binary $TEST_BUILD/test/$b was not built" >&2; exit 1; }
done

# The KAT probe: same NORMAL flags, linked against the CLEAN static library.
LIBWM_TEST="$TEST_BUILD/src/libWildMidi.a"
[ -f "$LIBWM_TEST" ] || { echo "FATAL: clean $LIBWM_TEST was not produced" >&2; exit 1; }
$CC -O2 -I"$SRC/include" -I"$TEST_BUILD/include" \
    "$SRC/mayhem/kat/wildmidi_kat.c" "$LIBWM_TEST" -lm \
    -o "$TEST_BUILD/wildmidi_kat"

# The KAT probe MUST be dynamically linked, or verify-repo's LD_PRELOAD sabotage
# shim cannot neuter it and mayhem/test.sh silently stops being a behavioral
# oracle (SPEC 6.3). Assert it so a toolchain change fails the BUILD instead.
if ! file "$TEST_BUILD/wildmidi_kat" | grep -q 'dynamically linked'; then
  echo "FATAL: $TEST_BUILD/wildmidi_kat is not dynamically linked -- the sabotage" >&2
  echo "       check could not neuter it, which would make mayhem/test.sh a" >&2
  echo "       reward-hackable oracle." >&2
  file "$TEST_BUILD/wildmidi_kat" >&2
  exit 1
fi
echo "built wildmidi_kat (dynamically linked KAT probe) + upstream ctest suite"

echo "build.sh complete:"
ls -la /mayhem/fuzz_midi /mayhem/fuzz_xmi /mayhem/fuzz_mus \
       /mayhem/fuzz_midi-standalone /mayhem/fuzz_xmi-standalone /mayhem/fuzz_mus-standalone \
       /mayhem/fuzz_midi.dict /mayhem/fuzz_xmi.dict /mayhem/fuzz_mus.dict \
       "$TEST_BUILD/wildmidi_kat" 2>&1 || true
