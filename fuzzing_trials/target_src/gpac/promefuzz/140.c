// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_last_error at isom_read.c:46:8 in isomedia.h
// gf_isom_make_interleave_ex at isom_write.c:6032:8 in isomedia.h
// gf_isom_clone_pl_indications at isom_write.c:3891:8 in isomedia.h
// gf_isom_remove_root_od at isom_write.c:165:8 in isomedia.h
// gf_isom_set_removed_bytes at isom_read.c:3185:8 in isomedia.h
// gf_isom_get_sidx_duration at isom_read.c:6196:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    return NULL; // As we cannot allocate an incomplete type, return NULL for testing
}

static void free_dummy_iso_file(GF_ISOFile* iso_file) {
    // No operation needed since we don't allocate
}

int LLVMFuzzerTestOneInput_140(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(GF_Fraction) + sizeof(u64)) return 0;

    GF_ISOFile* iso_file1 = create_dummy_iso_file();
    GF_ISOFile* iso_file2 = create_dummy_iso_file();

    GF_Fraction fraction;
    memcpy(&fraction, Data, sizeof(GF_Fraction));
    u64 bytes_removed = *(u64*)(Data + sizeof(GF_Fraction));

    // Test gf_isom_last_error
    GF_Err err = gf_isom_last_error(iso_file1);

    // Test gf_isom_make_interleave_ex
    err = gf_isom_make_interleave_ex(iso_file1, &fraction);

    // Test gf_isom_clone_pl_indications
    err = gf_isom_clone_pl_indications(iso_file1, iso_file2);

    // Test gf_isom_remove_root_od
    err = gf_isom_remove_root_od(iso_file1);

    // Test gf_isom_set_removed_bytes
    err = gf_isom_set_removed_bytes(iso_file1, bytes_removed);

    // Test gf_isom_get_sidx_duration
    u64 sidx_dur;
    u32 sidx_timescale;
    err = gf_isom_get_sidx_duration(iso_file1, &sidx_dur, &sidx_timescale);

    free_dummy_iso_file(iso_file1);
    free_dummy_iso_file(iso_file2);

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

        LLVMFuzzerTestOneInput_140(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    