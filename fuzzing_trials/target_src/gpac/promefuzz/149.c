// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_get_original_duration at isom_read.c:986:5 in isomedia.h
// gf_isom_estimate_size at isom_write.c:5783:5 in isomedia.h
// gf_isom_get_first_mdat_start at isom_read.c:4163:5 in isomedia.h
// gf_isom_get_unused_box_bytes at isom_read.c:4195:5 in isomedia.h
// gf_isom_get_duration at isom_read.c:971:5 in isomedia.h
// gf_isom_get_track_duration at isom_read.c:1076:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "isomedia.h"

static void cleanup_isofile(GF_ISOFile *isofile) {
    if (isofile) {
        gf_isom_close(isofile);
    }
}

int LLVMFuzzerTestOneInput_149(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return 0;
    fwrite(Data, 1, Size, file);
    fclose(file);

    GF_ISOFile *isofile = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isofile) return 0;

    u64 duration = gf_isom_get_original_duration(isofile);
    u64 estimated_size = gf_isom_estimate_size(isofile);
    u64 mdat_start = gf_isom_get_first_mdat_start(isofile);
    u64 unused_box_bytes = gf_isom_get_unused_box_bytes(isofile);
    u64 total_duration = gf_isom_get_duration(isofile);
    
    // Test with different track numbers
    for (u32 trackNumber = 0; trackNumber < 5; ++trackNumber) {
        u64 track_duration = gf_isom_get_track_duration(isofile, trackNumber);
    }

    cleanup_isofile(isofile);
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

        LLVMFuzzerTestOneInput_149(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    