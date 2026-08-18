/*==============================================================================
 mayhem/harnesses/fuzz_midi.c -- libFuzzer harness over WildMIDI's public
 buffer-parsing entry point, WildMidi_OpenBuffer().

 NOT an upstream file: WildMIDI ships no fuzz harness and is not an OSS-Fuzz
 project, so this is hand-written for this integration.

 WHAT IT FUZZES.  WildMidi_OpenBuffer(buf, size) takes bytes directly (no
 filesystem I/O at all) and sniffs the music format from the buffer's own
 magic, dispatching to one of six INDEPENDENT per-format readers
 (src/wildmidi_lib.c:parse_midi_buffer):

     mangled (Gremlin RLE)  -> _WM_Unmangle + _WM_ParseNewHmp/Hmi  (f_hmp.c/f_hmi.c)
     "HMIMIDIP"             -> _WM_ParseNewHmp                     (f_hmp.c)
     "HMI-MIDISONG061595"   -> _WM_ParseNewHmi                     (f_hmi.c)
     "MUS\x1a"              -> _WM_ParseNewMus                     (f_mus.c)
     "FORM"                 -> _WM_ParseNewXmi                     (f_xmidi.c)
     "MMMD"                 -> _WM_ParseNewSmaf                    (f_smaf.c)
     anything else          -> _WM_ParseNewMidi                    (f_midi.c, plain SMF)

 Every reader then feeds the shared event/track builder in internal_midi.c.
 This target's seed corpus is standard MIDI (SMF), so it drives f_midi.c +
 internal_midi.c primarily; mayhem/fuzz_midi/fuzz_midi.dict carries the other
 formats' magic strings so the fuzzer can also reach the sibling readers.
 (The XMIDI/MUS *converters* -- xmi2mid.c / mus2mid.c, a wholly separate body
 of code from the f_*.c readers -- are covered by the fuzz_xmi / fuzz_mus
 targets, which call them directly.)

 THE INIT GOTCHA (see mayhem/build.sh + the PR notes).  WildMidi_OpenBuffer
 refuses to do anything until WildMidi_Init() has succeeded, and Init normally
 wants a patch/config file (a .cfg listing GUS patch files) -- a filesystem
 dependency we do not want in a harness.  WildMIDI ships an escape hatch for
 exactly this: the sentinel config name "@opl3" (WM_OPL3_CONFIG,
 include/synth.h).  With it, _WM_Init() skips config loading ENTIRELY and fills
 the internal patch table from an embedded DMXOPL bank rendered by the built-in
 Nuked OPL3 emulator (src/wildmidi_lib.c:1781 -> src/synth.c:_WM_opl3_init_patches,
 a pure in-memory operation).  So this harness performs NO file I/O of any kind
 -- no relative read, no absolute read, no /dev/shm staging -- which is what
 SPEC 6.2 item 13 wants.  Init runs exactly ONCE, behind a first-call guard.

 BOUNDEDNESS (SPEC 6b).  The harness opens and closes; it never calls
 WildMidi_GetOutput(), because rendering audio from an attacker-controlled
 tempo/division/loop-count can run effectively unbounded and one such input
 would stall the whole campaign.  Parsing is the attack surface under test.

 Crashes and allocation failures are deliberately NOT guarded here -- those are
 the robustness findings the maintainers want.
 =============================================================================*/
#include <stddef.h>
#include <stdint.h>

#include "wildmidi_lib.h"

/* "@opl3" == WM_OPL3_CONFIG (include/synth.h). Spelled literally so the harness
 * needs no internal header. */
#define WM_HARNESS_OPL3_CONFIG "@opl3"

static int wm_ready = -1; /* -1 = not tried, 0 = Init failed, 1 = ready */

static void wm_init_once(void) {
    if (wm_ready >= 0) {
        return;
    }
    wm_ready = (WildMidi_Init(WM_HARNESS_OPL3_CONFIG, 44100, 0) == 0) ? 1 : 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    midi *song;

    wm_init_once();
    if (wm_ready != 1) {
        /* Init failing is a build/environment problem, not an input property.
         * Abort loudly rather than silently fuzzing a no-op. */
        __builtin_trap();
    }

    if (Size > 0xFFFFFFFFu) {
        return 0; /* WildMidi_OpenBuffer's size argument is a uint32_t */
    }

    song = WildMidi_OpenBuffer(Data, (uint32_t) Size);
    if (song != NULL) {
        /* Read the parsed metadata so the parse results are actually consumed
         * (and a bogus handle is caught), then release. No GetOutput() -- see
         * the BOUNDEDNESS note above. */
        struct _WM_Info *info = WildMidi_GetInfo(song);
        if (info != NULL) {
            volatile uint32_t sink = info->total_midi_time
                                   + info->approx_total_samples;
            (void) sink;
        }
        WildMidi_Close(song);
    }

    /* WildMIDI retains the LAST error message in a malloc'd global
     * (_WM_Global_ErrorS, src/wm_error.c) and hands ownership back through the
     * public WildMidi_ClearError(). Releasing it per iteration is ordinary use
     * of that API -- without it LeakSanitizer reports the retained buffer at
     * exit for any input that errored, drowning out real leaks. It does NOT
     * mask the genuine bug documented in
     * mayhem/fuzz_mus/known-findings/: _WM_ERROR_NEW() overwrites
     * _WM_Global_ErrorS WITHOUT freeing the old string, so two error reports
     * inside ONE iteration still leak and are still reported. */
    WildMidi_ClearError();

    return 0;
}
