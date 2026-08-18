#!/usr/bin/env bash
#
# wildmidi/mayhem/test.sh -- RUN WildMIDI's own ctest suite PLUS a set of direct
# known-answer assertions, and emit one CTRF summary. exit 0 iff nothing failed.
# This script does NOT compile: mayhem/build.sh already built everything in
# cmake-build-test/ with the project's NORMAL (non-sanitized) flags.
#
# TWO LAYERS, AND THE SECOND ONE IS THE ORACLE.
#
#  1) `ctest` over WildMIDI's five registered cases (test/CMakeLists.txt:
#     tokenize, smaf_sequ, ma7_voice, smaf_mtsp, smaf_7f23). These are real
#     assert()-based known-answer tests -- test_smaf_sequ.c, for instance, builds
#     an MMMD/SEQU container in memory, runs _WM_smaf2midi over it and asserts
#     the exact emitted MIDI byte runs (0xb1 0x07 0x50, 0x91 0x3e 0x64, ...).
#     Worth running, but NOT sufficient as the oracle:
#
#     WHY NOT: every one of them communicates ONLY through its exit code (they
#     print nothing on success), and ctest judges a case purely by that exit
#     code. verify-repo's anti-reward-hack sabotage shim is an LD_PRELOAD library
#     whose constructor _exit(0)s every non-system executable -- so each test
#     binary under cmake-build-test/ exits 0 before running a single assert, and
#     ctest cheerfully reports "100% tests passed" having proved nothing. That is
#     the same false-green as the `go test`/`cargo test`/`meson test` trap in
#     SPEC 6.3, reached by a different route (a neutered dynamic binary that
#     exits before doing any work).
#
#  2) DIRECT known-answer assertions against mayhem/kat/wildmidi_kat.c. The probe
#     drives the same three library paths the Mayhem harnesses fuzz and PRINTS
#     the values it computed; this script then compares those lines with
#     `grep -qxF` from bash. bash and coreutils are system binaries the sabotage
#     shim spares, so the comparison happens where sabotage cannot hide: a
#     neutered (or stubbed, or no-op-patched) libWildMidi prints nothing, every
#     grep misses, and this script FAILS loudly.
#
#     The asserted values are all computed by the library from fixed input:
#       * test/test.mid (WildMIDI's OWN committed fixture) parsed through
#         WildMidi_Init("@opl3") + WildMidi_OpenBuffer() -- the fuzz_midi path --
#         yields total_midi_time = 90353 (ms) and a rendered length of 90353 ms
#         at 44100 Hz. Both come out of the SMF's division + tempo events, so a
#         parser that stops parsing cannot produce them.
#       * a minimal DOOM MUS score converted by _WM_mus2midi() -- the fuzz_mus
#         path -- yields a 41-byte SMF (FNV-1a 946431023).
#       * a minimal XMIDI container converted by _WM_xmi2midi() -- the fuzz_xmi
#         path -- yields a 26-byte SMF (FNV-1a 2287456085).
#     Every probe is UNCONDITIONAL: a missing binary or fixture is a FAILURE,
#     never a skip.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

TEST_BUILD="$SRC/cmake-build-test"
KAT_BIN="$TEST_BUILD/wildmidi_kat"
KAT_FIXTURE="test/test.mid"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -d "$TEST_BUILD" ]; then
  echo "missing $TEST_BUILD -- run mayhem/build.sh first" >&2
  emit_ctrf "ctest+wildmidi-kat" 0 1 0; exit 2
fi

PASSED=0; FAILED=0; SKIPPED=0

# ── 1) WildMIDI's own ctest suite ────────────────────────────────────────────
echo "=== running: ctest (cmake-build-test) ==="
if ! command -v ctest >/dev/null 2>&1; then
  echo "FAIL: ctest not available" >&2
  FAILED=$(( FAILED + 1 ))
else
  out="$(cd "$TEST_BUILD" && ctest --output-on-failure 2>&1)"; rc=$?
  printf '%s\n' "$out"
  # "N% tests passed, F tests failed out of T"
  SUMMARY_LINE="$(printf '%s\n' "$out" | grep -m1 'tests passed,.*tests failed out of')"
  if [ -z "$SUMMARY_LINE" ]; then
    echo "FAIL: no ctest summary line (ctest exit $rc) -- the suite did not run" >&2
    FAILED=$(( FAILED + 1 ))
  else
    CFAIL="$(printf '%s' "$SUMMARY_LINE" | sed -nE 's/.*, ([0-9]+) tests failed out of ([0-9]+).*/\1/p')"
    CTOTAL="$(printf '%s' "$SUMMARY_LINE" | sed -nE 's/.*, ([0-9]+) tests failed out of ([0-9]+).*/\2/p')"
    : "${CFAIL:=0}" "${CTOTAL:=0}"
    if [ "$CTOTAL" -eq 0 ]; then
      echo "FAIL: ctest reports 0 tests out of 0 -- the suite is empty" >&2
      FAILED=$(( FAILED + 1 ))
    else
      PASSED=$(( PASSED + CTOTAL - CFAIL ))
      FAILED=$(( FAILED + CFAIL ))
      echo "ctest: $(( CTOTAL - CFAIL )) passed, $CFAIL failed, out of $CTOTAL"
    fi
  fi
fi

# ── 2) direct known-answer assertions (the sabotage-detecting oracle) ────────
echo "=== running: $KAT_BIN $KAT_FIXTURE ==="
KAT_OUT=""
if [ ! -x "$KAT_BIN" ]; then
  echo "FAIL: missing KAT probe $KAT_BIN -- run mayhem/build.sh first" >&2
  FAILED=$(( FAILED + 1 ))
elif [ ! -f "$KAT_FIXTURE" ]; then
  echo "FAIL: missing upstream fixture $SRC/$KAT_FIXTURE" >&2
  FAILED=$(( FAILED + 1 ))
else
  KAT_OUT="$("$KAT_BIN" "$KAT_FIXTURE" 2>&1)"; krc=$?
  printf '%s\n' "$KAT_OUT"
  [ "$krc" -eq 0 ] || echo "note: KAT probe exited $krc" >&2
fi

# kat_assert <expected exact line> -- UNCONDITIONAL: empty output fails every one.
kat_assert() {
  local want="$1"
  if printf '%s\n' "$KAT_OUT" | grep -qxF "$want"; then
    echo "KAT PASS: $want"; PASSED=$(( PASSED + 1 ))
  else
    echo "KAT FAIL: expected the line [$want] in the probe's output" >&2
    FAILED=$(( FAILED + 1 ))
  fi
}

# fuzz_midi path: WildMidi_Init("@opl3") + WildMidi_OpenBuffer(test/test.mid)
kat_assert 'KAT init=0'
kat_assert 'KAT smf_bytes=20467'
kat_assert 'KAT smf_total_midi_time=90353'
kat_assert 'KAT smf_length_ms=90353'
# fuzz_mus path: _WM_mus2midi() over a minimal DOOM MUS score
kat_assert 'KAT mus2mid_outsize=41'
kat_assert 'KAT mus2mid_sum=946431023'
# fuzz_xmi path: _WM_xmi2midi() over a minimal XMIDI container
kat_assert 'KAT xmi2mid_outsize=26'
kat_assert 'KAT xmi2mid_sum=2287456085'
# the probe's own self-report, so a partially-broken run cannot look clean
kat_assert 'KAT failures=0'

echo "=== results: $PASSED passed, $FAILED failed, $SKIPPED skipped ==="
emit_ctrf "ctest+wildmidi-kat" "$PASSED" "$FAILED" "$SKIPPED"
