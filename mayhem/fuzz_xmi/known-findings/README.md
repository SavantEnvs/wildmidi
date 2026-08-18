# fuzz_xmi — known findings

Found during integration, within ~90 s of fuzzing from the committed seeds. Kept here and NOT in
`testsuite/`: seeds are replayed on every run, so a crashing seed would abort every future run.

Reproduce:

```
/mayhem/fuzz_xmi-standalone mayhem/fuzz_xmi/known-findings/signed-shift-overflow-read4.xmi
```

---

## 1. `signed-shift-overflow-read4.xmi` — signed-integer-overflow UB in `xmi2mid.c`'s `read4()`

```
src/xmi2mid.c:113:42: runtime error: left shift of 146 by 24 places cannot be represented in type 'int'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/xmi2mid.c:113
```

**Cause.** `read4()` assembles a big-endian 32-bit chunk length out of four `uint8_t` locals:

```c
static uint32_t read4(struct xmi_ctx *ctx)
{
    uint8_t b0, b1, b2, b3;
    ...
    return (b0 + (b1<<8) + (b2<<16) + (b3<<24));   /* line 113 */
}
```

Each `uint8_t` is integer-promoted to `int`, so for any high byte ≥ 0x80 the `b3 << 24` shifts a bit
into (or past) the sign bit of a 32-bit `int` — undefined behaviour, and with `-fno-sanitize-recover`
a hard abort. Any XMIDI chunk length whose most-significant byte has the high bit set triggers it.

This is the same class of bug upstream fixed elsewhere in commit *"Fix signed-integer-overflow UB in
big-endian 32-bit reads across the format parsers"* (#293) — `xmi2mid.c`'s own private `read4()` was
missed by that sweep.

**Impact.** Undefined behaviour on attacker-supplied input in the XMIDI converter
(`WildMidi_ConvertToMidi`/`ConvertBufferToMidi` and the `f_xmidi.c` reader path both route chunk
lengths through it). In practice the UB result is a wrong/negative length, which then feeds
`seeksrc()`/`skipsrc()` arithmetic — so it is also the entry point to further out-of-range chunk
walking, not merely a pedantic sanitizer complaint.

**One-line upstream fix** — do the arithmetic in `uint32_t`:

```c
return ((uint32_t)b0 + ((uint32_t)b1<<8) + ((uint32_t)b2<<16) + ((uint32_t)b3<<24));
```

(equivalently, declare `b0..b3` as `uint32_t`, which is how the sibling readers were fixed).

**Reproducer** (67 bytes): a valid `FORM XDIR` header (1 track) followed by a `CAT ` chunk whose
`XMID` body is padded with `0x92` bytes, so the next `read4()` reads `92 92 92 92` as a chunk length.
