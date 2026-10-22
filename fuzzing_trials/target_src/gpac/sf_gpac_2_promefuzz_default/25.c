// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_set_movie_duration at movie_fragments.c:61:8 in isomedia.h
// gf_isom_reset_tables at isom_read.c:3407:8 in isomedia.h
// gf_isom_release_segment at isom_read.c:3459:8 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_freeze_order at isom_read.c:76:8 in isomedia.h
// gf_isom_flush_fragments at movie_fragments.c:1469:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "isomedia.h"

// Dummy structure size for allocation purposes
#define DUMMY_ISOFILE_SIZE 1024

static GF_ISOFile* create_dummy_iso_file() {
    // Allocate memory for GF_ISOFile
    GF_ISOFile* iso_file = (GF_ISOFile*)malloc(DUMMY_ISOFILE_SIZE);
    if (iso_file) {
        memset(iso_file, 0, DUMMY_ISOFILE_SIZE);
    }
    return iso_file;
}

static void cleanup_iso_file(GF_ISOFile* iso_file) {
    if (iso_file) {
        free(iso_file);
    }
}

int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    GF_ISOFile* iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    // Test gf_isom_set_movie_duration
    u64 duration = 0;
    if (Size >= sizeof(u64)) {
        duration = *(u64*)Data;
    }
    Bool remove_mehd = Data[0] % 2;
    gf_isom_set_movie_duration(iso_file, duration, remove_mehd);

    // Test gf_isom_reset_tables
    Bool reset_sample_count = Data[0] % 2;
    gf_isom_reset_tables(iso_file, reset_sample_count);

    // Test gf_isom_release_segment
    Bool reset_tables = Data[0] % 2;
    gf_isom_release_segment(iso_file, reset_tables);

    // Test gf_isom_reset_data_offset
    u64 top_box_start = 0;
    if (Size >= sizeof(u64)) {
        top_box_start = *(u64*)Data;
    }
    gf_isom_reset_data_offset(iso_file, &top_box_start);

    // Test gf_isom_freeze_order
    gf_isom_freeze_order(iso_file);

    // Test gf_isom_flush_fragments
    Bool last_segment = Data[0] % 2;
    gf_isom_flush_fragments(iso_file, last_segment);

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

        LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    