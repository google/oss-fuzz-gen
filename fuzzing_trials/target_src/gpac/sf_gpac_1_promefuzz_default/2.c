// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_set_next_moof_number at movie_fragments.c:3477:6 in isomedia.h
// gf_isom_reset_sample_count at isom_read.c:5005:6 in isomedia.h
// gf_isom_get_timescale at isom_read.c:962:5 in isomedia.h
// gf_isom_guess_specification at isom_read.c:4276:5 in isomedia.h
// gf_isom_enable_traf_map_templates at isom_read.c:6026:6 in isomedia.h
// gf_isom_disable_inplace_rewrite at isom_write.c:9177:6 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Provide a dummy directory path for the third parameter
    return gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, "/tmp");
}

static void cleanup_iso_file(GF_ISOFile *file) {
    if (file) {
        gf_isom_close(file);
    }
}

int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;

    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    u32 value = *((u32*)Data);

    // Test gf_isom_set_next_moof_number
    gf_isom_set_next_moof_number(iso_file, value);

    // Test gf_isom_reset_sample_count
    gf_isom_reset_sample_count(iso_file);

    // Test gf_isom_get_timescale
    u32 timescale = gf_isom_get_timescale(iso_file);
    (void)timescale; // Suppress unused variable warning

    // Test gf_isom_guess_specification
    u32 spec = gf_isom_guess_specification(iso_file);
    (void)spec; // Suppress unused variable warning

    // Test gf_isom_enable_traf_map_templates
    gf_isom_enable_traf_map_templates(iso_file);

    // Test gf_isom_disable_inplace_rewrite
    gf_isom_disable_inplace_rewrite(iso_file);

    cleanup_iso_file(iso_file);

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

        LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    