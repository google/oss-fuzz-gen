// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_set_next_moof_number at movie_fragments.c:3474:6 in isomedia.h
// gf_isom_reset_sample_count at isom_read.c:5005:6 in isomedia.h
// gf_isom_get_pssh_count at isom_read.c:5559:5 in isomedia.h
// gf_isom_set_progress_callback at isom_write.c:8548:6 in isomedia.h
// gf_isom_segment_get_fragment_count at isom_read.c:864:5 in isomedia.h
// gf_isom_delete at isom_read.c:2899:6 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "isomedia.h"

#define DUMMY_FILE_PATH "./dummy_file"

static void dummy_progress_callback(void *udta, u64 nb_done, u64 nb_total) {
    // Dummy progress callback function
}

int LLVMFuzzerTestOneInput_99(const uint8_t *Data, size_t Size) {
    // Create a dummy file to satisfy file operations
    FILE *dummy_file = fopen(DUMMY_FILE_PATH, "wb");
    if (!dummy_file) return 0;
    fwrite(Data, 1, Size, dummy_file);
    fclose(dummy_file);

    // Allocate and initialize a GF_ISOFile structure
    GF_ISOFile *isom_file = gf_isom_open(DUMMY_FILE_PATH, GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    // Fuzz gf_isom_set_next_moof_number
    if (Size >= sizeof(u32)) {
        u32 moof_number = *(u32 *)Data;
        gf_isom_set_next_moof_number(isom_file, moof_number);
    }

    // Fuzz gf_isom_reset_sample_count
    gf_isom_reset_sample_count(isom_file);

    // Fuzz gf_isom_get_pssh_count
    u32 pssh_count = gf_isom_get_pssh_count(isom_file);

    // Fuzz gf_isom_set_progress_callback
    gf_isom_set_progress_callback(isom_file, dummy_progress_callback, NULL);

    // Fuzz gf_isom_segment_get_fragment_count
    u32 fragment_count = gf_isom_segment_get_fragment_count(isom_file);

    // Cleanup
    gf_isom_delete(isom_file);
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

        LLVMFuzzerTestOneInput_99(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    