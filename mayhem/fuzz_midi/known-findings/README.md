# fuzz_midi — known findings

Found during integration, within ~90 s of fuzzing from the committed seeds. Kept here and NOT in
`testsuite/`: seeds are replayed on every run, so a crashing seed would abort every future run.

Reproduce (both binaries are produced by `mayhem/build.sh`):

```
/mayhem/fuzz_midi-standalone mayhem/fuzz_midi/known-findings/heap-overflow-noteon-velocity-peek.mid
```

---

## 1. `heap-overflow-noteon-velocity-peek.mid` — 1-byte heap out-of-bounds READ in `_WM_SetupMidiEvent`

```
ERROR: AddressSanitizer: heap-buffer-overflow ... READ of size 1
    #0 _WM_SetupMidiEvent  src/internal_midi.c:2252
    #1 _WM_ParseNewMidi    src/f_midi.c:366
    #2 parse_midi_buffer   src/wildmidi_lib.c:1976
    #3 WildMidi_OpenBuffer src/wildmidi_lib.c:2036
0x... is located 0 bytes after 37-byte region
```

**Cause — the bounds check runs *after* the byte it protects is read.** In the note-on case of
`_WM_SetupMidiEvent` (`src/internal_midi.c`):

```c
case 0x90:
    if (event_data[1] == 0) goto _SETUP_NOTEOFF;  /* <-- line 2252: reads data byte 2 */
    if (input_length < 2) goto shortbuf;          /* <-- the check that would have stopped it */
```

The velocity byte is peeked (a note-on with velocity 0 is remapped to a note-off) *before*
`input_length` is validated, so a track whose last event is a note-on with only the note number
present reads one byte past the end of the caller's buffer. Note the very next case, `0x80`, has the
two lines in the correct order — this is a local ordering slip, not a design gap.

**Impact.** Out-of-bounds read of one heap byte on attacker-supplied MIDI data, on the library's main
public path (`WildMidi_Open`/`WildMidi_OpenBuffer` → SMF reader). With WildMIDI's own allocation it
usually lands in slack; when the file is parsed from a buffer the caller sized exactly (which is what
`WildMidi_OpenBuffer` invites, and what this harness does), it is a genuine overread — crash under a
hardened allocator, and the peeked value changes control flow (note-on vs note-off), so it is
observable, not inert.

**One-line upstream fix** — swap the two lines so the length is checked first:

```c
case 0x90:
    if (input_length < 2) goto shortbuf;
    if (event_data[1] == 0) goto _SETUP_NOTEOFF;
```

**Reproducer** (37 bytes): a type-0 SMF, division 96, one `MTrk` of 15 bytes holding
`00 C0 00 | 00 90 3C 64 | 60 2A 3C 40 | 00 FF 2F 00` — the running-status note event near the end of
the track leaves a single data byte before the buffer ends when `_WM_SetupMidiEvent` reaches it.
