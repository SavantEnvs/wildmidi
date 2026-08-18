/*==============================================================================
 mayhem/kat/wildmidi_kat.c -- known-answer-test probe for mayhem/test.sh.

 NOT an upstream file.  WildMIDI's own registered ctest cases (test/test_*.c)
 are assert()-based: they print NOTHING on success and communicate purely
 through their exit code, so `ctest` alone is an exit-code-only oracle -- and
 verify-repo's sabotage shim (an LD_PRELOAD constructor that _exit(0)s every
 non-system binary) makes every one of them "pass" without executing a line.
 See the header of mayhem/test.sh.

 This probe closes that hole: it drives the SAME library code the three Mayhem
 harnesses fuzz and PRINTS the computed values, so mayhem/test.sh can assert
 exact strings from bash (where the shim cannot hide).  A neutered or stubbed
 library prints nothing / different numbers, and the grep assertions fail.

 It exercises three independent code paths, one per fuzz target:

   1. WildMidi_Init("@opl3") + WildMidi_OpenBuffer(): the public parse entry
      point behind mayhem/harnesses/fuzz_midi.c -- run over WildMIDI's OWN
      committed fixture test/test.mid (argv[1]).  Asserts the parsed SMF's
      track/division metadata and the computed song length.
   2. _WM_mus2midi(): the DOOM-MUS -> SMF converter behind fuzz_mus, over a
      minimal MUS score built in-memory below.
   3. _WM_xmi2midi(): the XMIDI -> SMF converter behind fuzz_xmi, over a
      minimal XMI container built in-memory below.

 Output is one `KAT <key>=<value>` line per assertion, printed on stdout in a
 fixed order.  Any failure to reach a value is reported as `KAT <key>=ERROR`
 (never silence-and-exit-0), so the caller's exact-match greps fail loudly.

 The "@opl3" sentinel (WM_OPL3_CONFIG, include/synth.h) makes WildMidi_Init
 populate its patch table from the built-in Nuked-OPL3 bank instead of reading
 a GUS .cfg patch file -- so this probe needs no config file either.
 =============================================================================*/
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wildmidi_lib.h"
#include "mus2mid.h"
#include "xmi2mid.h"

#define KAT_RATE 44100

/* A stable, order-sensitive checksum over a byte range: enough to pin the
 * converters' exact output without committing a 100-byte golden blob. */
static uint32_t kat_sum(const uint8_t *p, uint32_t n) {
    uint32_t h = 2166136261u, i;
    for (i = 0; i < n; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

/* ---- fixture 1: WildMIDI's own test/test.mid, path from argv[1] ---------- */
static uint8_t *slurp(const char *path, uint32_t *size_out) {
    FILE *f = fopen(path, "rb");
    long n;
    uint8_t *buf;
    if (f == NULL) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    n = ftell(f);
    if (n <= 0) { fclose(f); return NULL; }
    rewind(f);
    buf = (uint8_t *) malloc((size_t) n);
    if (buf == NULL) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t) n, f) != (size_t) n) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *size_out = (uint32_t) n;
    return buf;
}

/* ---- fixture 2: a minimal DOOM MUS score (same bytes as the fuzz_mus seed) */
/* MUS\x1a | scoreLen=1 | scoreStart=16 | channels=0 | sec_channels=0 |
   instrCnt=0 | pad | score: 0x60 = "score end" event, terminating byte.      */
static const uint8_t kat_mus[] = {
    'M', 'U', 'S', 0x1A,
    0x01, 0x00,             /* scoreLen    = 1  */
    0x10, 0x00,             /* scoreStart  = 16 */
    0x00, 0x00,             /* channels        */
    0x00, 0x00,             /* sec_channels    */
    0x00, 0x00,             /* instrCnt    = 0  */
    0x00, 0x00,             /* padding          */
    0x60, 0x00, 0x00        /* score: end-of-score event                      */
};

/* ---- fixture 3: a minimal XMIDI container (same bytes as the fuzz_xmi seed) */
/* FORM <14> XDIR INFO <2> ntracks=1  (little-endian, xmi2mid.c:read2)
   CAT  <28> XMID FORM <16> XMID EVNT <4> { delay 0, FF 2F 00 = end-of-track }
   The chunk lengths and the (len+1)&~1 word alignment matter: xmi2mid.c's
   ParseXMI seeks to start + ((len+1)&~1) to find the CAT  chunk, so an
   off-by-one length makes the whole file "not an XMIDI".                     */
static const uint8_t kat_xmi[] = {
    'F','O','R','M', 0x00,0x00,0x00,0x0E,
    'X','D','I','R',
    'I','N','F','O', 0x00,0x00,0x00,0x02, 0x01,0x00,
    'C','A','T',' ', 0x00,0x00,0x00,0x1C,
    'X','M','I','D',
    'F','O','R','M', 0x00,0x00,0x00,0x10,
    'X','M','I','D',
    'E','V','N','T', 0x00,0x00,0x00,0x04, 0x00,0xFF,0x2F,0x00
};

int main(int argc, char **argv) {
    uint8_t *smf = NULL;
    uint32_t smf_size = 0;
    midi *song = NULL;
    struct _WM_Info *info = NULL;
    uint8_t *out = NULL;
    uint32_t outsize = 0;
    int rc, failures = 0;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <path-to-test.mid>\n", argv[0]);
        return 2;
    }

    /* ── 1) the public reader path (fuzz_midi) ───────────────────────────── */
    smf = slurp(argv[1], &smf_size);
    if (smf == NULL) {
        printf("KAT smf_bytes=ERROR\n");
        fprintf(stderr, "KAT: cannot read fixture '%s'\n", argv[1]);
        failures++;
    } else {
        printf("KAT smf_bytes=%u\n", smf_size);
    }

    rc = WildMidi_Init("@opl3", KAT_RATE, 0);
    printf("KAT init=%d\n", rc);
    if (rc != 0) {
        fprintf(stderr, "KAT: WildMidi_Init(\"@opl3\") failed: %s\n",
                WildMidi_GetError() ? WildMidi_GetError() : "(no error text)");
        failures++;
    }

    if (rc == 0 && smf != NULL) {
        song = WildMidi_OpenBuffer(smf, smf_size);
    }
    if (song == NULL) {
        printf("KAT smf_total_midi_time=ERROR\n");
        printf("KAT smf_length_ms=ERROR\n");
        fprintf(stderr, "KAT: WildMidi_OpenBuffer failed: %s\n",
                WildMidi_GetError() ? WildMidi_GetError() : "(no error text)");
        failures++;
    } else {
        info = WildMidi_GetInfo(song);
        if (info == NULL) {
            printf("KAT smf_total_midi_time=ERROR\n");
            printf("KAT smf_length_ms=ERROR\n");
            fprintf(stderr, "KAT: WildMidi_GetInfo returned NULL\n");
            failures++;
        } else {
            /* total_midi_time is in 1/1000 s units; approx_total_samples is the
             * rendered length at KAT_RATE. Both are computed by the parser from
             * the file's division + tempo events, so they pin real behaviour. */
            printf("KAT smf_total_midi_time=%u\n", info->total_midi_time);
            printf("KAT smf_length_ms=%u\n",
                   (unsigned) ((uint64_t) info->approx_total_samples * 1000u / KAT_RATE));
        }
        WildMidi_Close(song);
    }

    /* ── 2) the MUS converter path (fuzz_mus) ────────────────────────────── */
    out = NULL; outsize = 0;
    rc = _WM_mus2midi(kat_mus, (uint32_t) sizeof(kat_mus), &out, &outsize, 0);
    if (rc != 0 || out == NULL || outsize < 14 || memcmp(out, "MThd", 4) != 0) {
        printf("KAT mus2mid_outsize=ERROR\n");
        printf("KAT mus2mid_sum=ERROR\n");
        fprintf(stderr, "KAT: _WM_mus2midi failed (rc=%d outsize=%u)\n", rc, outsize);
        failures++;
    } else {
        printf("KAT mus2mid_outsize=%u\n", outsize);
        printf("KAT mus2mid_sum=%u\n", kat_sum(out, outsize));
    }
    free(out);

    /* ── 3) the XMI converter path (fuzz_xmi) ────────────────────────────── */
    out = NULL; outsize = 0;
    rc = _WM_xmi2midi(kat_xmi, (uint32_t) sizeof(kat_xmi), &out, &outsize,
                      XMIDI_CONVERT_NOCONVERSION);
    if (rc != 0 || out == NULL || outsize < 14 || memcmp(out, "MThd", 4) != 0) {
        printf("KAT xmi2mid_outsize=ERROR\n");
        printf("KAT xmi2mid_sum=ERROR\n");
        fprintf(stderr, "KAT: _WM_xmi2midi failed (rc=%d outsize=%u)\n", rc, outsize);
        failures++;
    } else {
        printf("KAT xmi2mid_outsize=%u\n", outsize);
        printf("KAT xmi2mid_sum=%u\n", kat_sum(out, outsize));
    }
    free(out);

    free(smf);
    WildMidi_Shutdown();

    printf("KAT failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
