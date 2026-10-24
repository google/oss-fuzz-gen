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
#include <stdio.h>
#include "isomedia.h"

// Define a dummy size for GF_ISOFile since we don't have the actual structure size
#define DUMMY_ISOFILE_SIZE 1024

static GF_ISOFile* create_dummy_isofile() {
    // Allocate memory for the GF_ISOFile structure
    GF_ISOFile* file = (GF_ISOFile*)malloc(DUMMY_ISOFILE_SIZE);
    if (!file) return NULL;
    memset(file, 0, DUMMY_ISOFILE_SIZE);
    return file;
}

static void cleanup_isofile(GF_ISOFile* file) {
    if (file) {
        free(file);
    }
}

int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u64)) return 0;

    GF_ISOFile* isom_file = create_dummy_isofile();
    if (!isom_file) return 0;

    u64 duration = *((u64*)Data);
    Bool remove_mehd = (Size > sizeof(u64)) ? Data[sizeof(u64)] % 2 : 0;

    gf_isom_set_movie_duration(isom_file, duration, remove_mehd);

    Bool reset_sample_count = (Size > sizeof(u64) + 1) ? Data[sizeof(u64) + 1] % 2 : 0;
    gf_isom_reset_tables(isom_file, reset_sample_count);

    Bool reset_tables = (Size > sizeof(u64) + 2) ? Data[sizeof(u64) + 2] % 2 : 0;
    gf_isom_release_segment(isom_file, reset_tables);

    u64 top_box_start = 0;
    gf_isom_reset_data_offset(isom_file, &top_box_start);

    gf_isom_freeze_order(isom_file);

    Bool last_segment = (Size > sizeof(u64) + 3) ? Data[sizeof(u64) + 3] % 2 : 0;
    gf_isom_flush_fragments(isom_file, last_segment);

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

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    