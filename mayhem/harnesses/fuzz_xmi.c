/*==============================================================================
 mayhem/harnesses/fuzz_xmi.c -- libFuzzer harness over WildMIDI's XMIDI (XMI)
 -> standard-MIDI converter, _WM_xmi2midi() (src/xmi2mid.c, ~1100 lines).

 NOT an upstream file (WildMIDI ships no fuzz harness; it is not an OSS-Fuzz
 project).

 WHY THE INTERNAL ENTRY POINT.  WildMIDI has TWO independent bodies of code per
 exotic format: the *reader* that builds a synth event stream (src/f_xmidi.c,
 reached via WildMidi_OpenBuffer -- see mayhem/harnesses/fuzz_midi.c) and the
 *converter* that rewrites the file as an SMF (src/xmi2mid.c, reached via
 WildMidi_ConvertBufferToMidi).  Calling _WM_xmi2midi() directly gives this
 target the converter with NO magic-byte gate in front of it: every mutated
 input lands in the XMIDI chunk walker, instead of most of them being rejected
 by a "FORM" prefix test.  It also needs no WildMidi_Init(), so no patch/config
 file and no filesystem access of any kind (SPEC 6.2 item 13).

 The symbol is a plain (non-static) internal function declared in
 include/xmi2mid.h; WildMIDI's own upstream tests reach internal converters the
 same way (see test/test_smaf_sequ.c, which declares _WM_smaf2midi extern).

 BOUNDEDNESS (SPEC 6b): conversion is a single pass over the input chunk tree
 and allocates the output SMF; no audio is rendered, so an iteration cannot
 spin on a malformed tempo/division the way GetOutput() could.

 Crashes / allocation failures are NOT guarded -- they are the findings.
 =============================================================================*/
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "wildmidi_lib.h"   /* WildMidi_ClearError */
#include "xmi2mid.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    uint8_t *out = NULL;
    uint32_t outsize = 0;

    if (Size > 0xFFFFFFFFu) {
        return 0; /* insize is a uint32_t */
    }

    if (_WM_xmi2midi(Data, (uint32_t) Size, &out, &outsize,
                     XMIDI_CONVERT_NOCONVERSION) == 0 && out != NULL) {
        /* Touch the produced SMF so the conversion result is consumed. */
        if (outsize > 0) {
            volatile uint8_t sink = out[0] ^ out[outsize - 1];
            (void) sink;
        }
    }
    free(out);

    /* Release WildMIDI's retained last-error string (src/wm_error.c's malloc'd
     * _WM_Global_ErrorS) through its own public API, so LeakSanitizer does not
     * report that expected retention at exit for every rejected input. This
     * does not hide the real defect recorded in
     * mayhem/fuzz_mus/known-findings/ -- two _WM_ERROR_NEW() reports inside one
     * iteration still leak, because _WM_ERROR_NEW overwrites the pointer
     * without freeing. */
    WildMidi_ClearError();

    return 0;
}
