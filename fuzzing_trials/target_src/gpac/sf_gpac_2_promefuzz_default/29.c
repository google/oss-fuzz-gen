// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_make_interleave_ex at isom_write.c:6151:8 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_set_byte_offset at isom_read.c:5910:8 in isomedia.h
// gf_isom_freeze_order at isom_read.c:76:8 in isomedia.h
// gf_isom_force_64bit_chunk_offset at isom_write.c:2788:8 in isomedia.h
// gf_isom_set_sample_group_in_traf at isom_write.c:8656:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile *initialize_isofile() {
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return isom_file;
}

static void cleanup_isofile(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

static GF_Fraction random_fraction() {
    GF_Fraction frac;
    frac.num = rand() % 100 + 1;
    frac.den = rand() % 100 + 1;
    return frac;
}

int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u64) + sizeof(s64)) return 0;

    GF_ISOFile *isom_file = initialize_isofile();
    if (!isom_file) return 0;

    // Fuzz gf_isom_make_interleave_ex
    GF_Fraction interleave_time = random_fraction();
    gf_isom_make_interleave_ex(isom_file, &interleave_time);

    // Fuzz gf_isom_reset_data_offset
    u64 top_box_start = *((u64 *)Data);
    gf_isom_reset_data_offset(isom_file, &top_box_start);

    // Fuzz gf_isom_set_byte_offset
    s64 byte_offset = *((s64 *)(Data + sizeof(u64)));
    gf_isom_set_byte_offset(isom_file, byte_offset);

    // Fuzz gf_isom_freeze_order
    gf_isom_freeze_order(isom_file);

    // Fuzz gf_isom_force_64bit_chunk_offset
    Bool set_on = (Data[0] % 2) == 0 ? GF_TRUE : GF_FALSE;
    gf_isom_force_64bit_chunk_offset(isom_file, set_on);

    // Fuzz gf_isom_set_sample_group_in_traf
    gf_isom_set_sample_group_in_traf(isom_file);

    cleanup_isofile(isom_file);
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

        LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    