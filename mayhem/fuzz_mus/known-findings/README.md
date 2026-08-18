# fuzz_mus — known findings

Found during integration, within ~90 s of fuzzing from the committed seeds. Kept here and NOT in
`testsuite/`: seeds are replayed on every run, so a crashing seed would abort every future run.

Reproduce:

```
/mayhem/fuzz_mus-standalone mayhem/fuzz_mus/known-findings/heap-overflow-keyoff-payload.mus
```

---

## 1. `heap-overflow-keyoff-payload.mus` — 1-byte heap out-of-bounds READ in `_WM_mus2midi`

```
ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 1
    #0 _WM_mus2midi  src/mus2mid.c:347
0x... is located 0 bytes after 25-byte region
```

**Cause — the loop bound covers the event byte but not the event's payload.** `_WM_mus2midi`
validates the header (`insize >= scoreLen + scoreStart`, so `end = in + scoreStart + scoreLen` is
within the buffer) and then walks the score:

```c
cur = in + header.scoreStart;
end = cur + header.scoreLen;
while (cur < end) {
    event = *cur++;                 /* in bounds: cur < end held */
    ...
    switch ((event & 122) >> 4) {
        case MUSEVENT_KEYOFF:
            status |= 0x80;
            bit1 = *cur++;          /* <-- line 347: NOT re-checked against end */
```

`cur < end` is only re-tested at the top of the loop, so when the last byte of the score is an event
byte its payload is read at `end`. When `scoreStart + scoreLen == insize` (exactly the tight-buffer
case `WildMidi_ConvertBufferToMidi` hands over) that is one byte past the caller's allocation. Every
event type in the switch reads 1–2 payload bytes the same unchecked way, so `KEYOFF` is simply the
shortest route to it.

**Impact.** Out-of-bounds read on attacker-supplied DOOM MUS data through a public entry point
(`WildMidi_ConvertToMidi` / `WildMidi_ConvertBufferToMidi`, and the same score layout reaches
`f_mus.c` for playback). The byte read is written into the emitted MIDI stream, so heap contents past
the buffer leak into the converter's output — an information disclosure, not just a crash. Note
`src/f_mus.c` *does* bound its equivalent walk (`GHSA-v6gx-9vh4-c8qx` hardened it); `mus2mid.c` was
not given the same treatment.

**One-line upstream fix** — bound the payload reads, e.g. guard each of them:

```c
case MUSEVENT_KEYOFF:
    status |= 0x80;
    if (cur >= end) goto _end;
    bit1 = *cur++;
```

(the robust form is a single `remaining = end - cur;` check against each event type's payload size,
right after `event = *cur++;`, covering all six cases at once).

**Reproducer** (25 bytes): `MUS\x1a`, `scoreLen = 9`, `scoreStart = 16`, so the score is bytes 16–24
and `end` lands exactly on the end of the 25-byte buffer; the score's zero bytes decode as
`MUSEVENT_KEYOFF` events, and the final one reads its note byte past `end`.

---

## 2. (secondary, not separately reproduced) `_WM_ERROR_NEW` overwrites the retained error string without freeing it

`src/wm_error.c`'s `_WM_GLOBAL_ERROR_INTERNAL` frees the previously retained message before
replacing it:

```c
if (_WM_Global_ErrorS != NULL) free(_WM_Global_ErrorS);
```

but `_WM_ERROR_NEW` (used by `mus2mid.c` ×3 and `xmi2mid.c` ×4) does not — it just assigns
`_WM_Global_ErrorS = errorstring;`. So every `_WM_ERROR_NEW` call after the first leaks 256 bytes
until `WildMidi_ClearError()` is called. A long-running host that keeps feeding malformed files (a
game scanning a music directory, a transcoder service) leaks steadily.

The harnesses call `WildMidi_ClearError()` at the end of each iteration — the library's own public
API for releasing that buffer — so LeakSanitizer is not swamped by the *expected* single retained
message; a genuine double-report inside one iteration is still reported.

**One-line upstream fix** — mirror the sibling function:

```c
void _WM_ERROR_NEW(const char * wmfmt, ...) {
    ...
    if (_WM_Global_ErrorS != NULL) free(_WM_Global_ErrorS);
    _WM_Global_ErrorS = errorstring;
```
