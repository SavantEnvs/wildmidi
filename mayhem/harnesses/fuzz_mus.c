/*==============================================================================
 mayhem/harnesses/fuzz_mus.c -- libFuzzer harness over WildMIDI's DOOM MUS ->
 standard-MIDI converter, _WM_mus2midi() (src/mus2mid.c).

 NOT an upstream file (WildMIDI ships no fuzz harness; it is not an OSS-Fuzz
 project).

 WHY THE INTERNAL ENTRY POINT.  As with fuzz_xmi, WildMIDI carries two
 independent bodies of MUS code: the reader that builds a synth event stream
 (src/f_mus.c, reached through WildMidi_OpenBuffer -- covered by the fuzz_midi
 target) and the converter that rewrites the MUS score as an SMF
 (src/mus2mid.c, reached through WildMidi_ConvertBufferToMidi).  Calling
 _WM_mus2midi() directly puts every mutated byte string into the MUS score
 walker with no "MUS\x1a" magic gate in front of it, and needs no
 WildMidi_Init() -- hence no patch/config file and NO filesystem access at all
 (SPEC 6.2 item 13).  The symbol is a plain internal function declared in
 include/mus2mid.h; WildMIDI's own tests reach internal converters the same way
 (test/test_smaf_sequ.c declares _WM_smaf2midi extern).

 BOUNDEDNESS (SPEC 6b): a single pass over the score plus the SMF write; no
 audio rendering, so no unbounded render loop from a malformed tempo.

 frequency = 0 lets mus2mid.c apply its own default (140 Hz), matching what
 WildMidi_ConvertBufferToMidi passes when WM_CO_FREQUENCY is unset.

 Crashes / allocation failures are NOT guarded -- they are the findings.
 =============================================================================*/
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "wildmidi_lib.h"   /* WildMidi_ClearError */
#include "mus2mid.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    uint8_t *out = NULL;
    uint32_t outsize = 0;

    if (Size > 0xFFFFFFFFu) {
        return 0; /* insize is a uint32_t */
    }

    /* On failure mus2mid.c sets *out = NULL, so the free() below is safe
       either way (src/mus2mid.c, the _end: cleanup block). */
    if (_WM_mus2midi(Data, (uint32_t) Size, &out, &outsize, 0) == 0
        && out != NULL && outsize > 0) {
        volatile uint8_t sink = out[0] ^ out[outsize - 1];
        (void) sink;
    }
    free(out);

    /* Release WildMIDI's retained last-error string (src/wm_error.c's malloc'd
     * _WM_Global_ErrorS) through its own public API, so LeakSanitizer does not
     * report that expected retention at exit for every rejected input. The real
     * defect is still reachable and still reported -- see
     * mayhem/fuzz_mus/known-findings/README.md: _WM_ERROR_NEW() overwrites
     * _WM_Global_ErrorS without freeing the previous string, so two error
     * reports within ONE iteration leak 256 bytes. */
    WildMidi_ClearError();

    return 0;
}
