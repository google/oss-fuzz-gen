// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_set_movie_duration at movie_fragments.c:61:8 in isomedia.h
// gf_isom_reset_tables at isom_read.c:3407:8 in isomedia.h
// gf_isom_release_segment at isom_read.c:3459:8 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_flush_fragments at movie_fragments.c:1469:8 in isomedia.h
// gf_isom_reset_track_switch_parameter at isom_write.c:7108:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "isomedia.h"

int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u64) + sizeof(Bool)) return 0;

    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    if (!isom_file) return 0;

    u64 duration = *((u64 *)Data);
    Bool remove_mehd = *((Bool *)(Data + sizeof(u64)));

    u64 top_box_start = 0;
    u32 trackNumber = 1;
    Bool reset_all_group = GF_FALSE;

    // Call the target functions with different parameters
    gf_isom_set_movie_duration(isom_file, duration, remove_mehd);
    gf_isom_reset_tables(isom_file, GF_TRUE);
    gf_isom_release_segment(isom_file, GF_TRUE);
    gf_isom_reset_data_offset(isom_file, &top_box_start);
    gf_isom_flush_fragments(isom_file, GF_TRUE);
    gf_isom_reset_track_switch_parameter(isom_file, trackNumber, reset_all_group);

    gf_isom_close(isom_file);
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

        LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    