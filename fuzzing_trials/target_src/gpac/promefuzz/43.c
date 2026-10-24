// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_text_set_wrap at tx3g.c:411:8 in isomedia.h
// gf_isom_text_to_sample at tx3g.c:472:15 in isomedia.h
// gf_isom_text_reset_styles at tx3g.c:612:8 in isomedia.h
// gf_isom_text_reset at tx3g.c:636:8 in isomedia.h
// gf_isom_new_text_sample at tx3g.c:602:16 in isomedia.h
// gf_isom_delete_text_sample at tx3g.c:646:6 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static void fuzz_gf_isom_text_set_wrap(GF_TextSample *sample, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    u8 wrap_flag = Data[0] % 2; // Only 0 or 1 are valid
    gf_isom_text_set_wrap(sample, wrap_flag);
}

static void fuzz_gf_isom_text_to_sample(GF_TextSample *sample) {
    GF_ISOSample *iso_sample = gf_isom_text_to_sample(sample);
    if (iso_sample) {
        // Free iso_sample if necessary
        free(iso_sample);
    }
}

static void fuzz_gf_isom_text_reset_styles(GF_TextSample *sample) {
    gf_isom_text_reset_styles(sample);
}

static void fuzz_gf_isom_text_reset(GF_TextSample *sample) {
    gf_isom_text_reset(sample);
}

int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size) {
    GF_TextSample *sample = gf_isom_new_text_sample();
    if (!sample) return 0;

    fuzz_gf_isom_text_set_wrap(sample, Data, Size);
    fuzz_gf_isom_text_to_sample(sample);
    fuzz_gf_isom_text_reset_styles(sample);
    fuzz_gf_isom_text_reset(sample);

    gf_isom_delete_text_sample(sample);
    return 0;
}
    #ifdef INC_MAIN
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdint.h>
    int main(int argc, char *argv[])
    {
        FILE *f;
        uint8_t *data = NULL;
        long size;

        if(argc < 2)
            exit(0);

        f = fopen(argv[1], "rb");
        if(f == NULL)
            exit(0);

        fseek(f, 0, SEEK_END);

        size = ftell(f);
        rewind(f);

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    