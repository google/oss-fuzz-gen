// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_refresh_size_info at stbl_write.c:2299:8 in isomedia.h
// gf_isom_set_ipod_compatible at isom_write.c:9114:8 in isomedia.h
// gf_isom_add_track_to_root_od at isom_write.c:136:8 in isomedia.h
// gf_isom_set_interleave_time at isom_write.c:3550:8 in isomedia.h
// gf_isom_remove_sample_group at isom_write.c:7751:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile *initialize_iso_file(const uint8_t *Data, size_t Size) {
    // Create a dummy file to simulate the ISO file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open the ISO file using the correct function signature
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return isom_file;
}

int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3) return 0;

    GF_ISOFile *isom_file = initialize_iso_file(Data, Size);
    if (!isom_file) return 0;

    u32 trackNumber = *((u32 *)Data);
    u32 InterleaveTime = *((u32 *)(Data + sizeof(u32)));
    u32 grouping_type = *((u32 *)(Data + 2 * sizeof(u32)));

    // Fuzz gf_isom_refresh_size_info
    gf_isom_refresh_size_info(isom_file, trackNumber);

    // Fuzz gf_isom_set_ipod_compatible
    gf_isom_set_ipod_compatible(isom_file, trackNumber);

    // Fuzz gf_isom_add_track_to_root_od
    gf_isom_add_track_to_root_od(isom_file, trackNumber);

    // Fuzz gf_isom_set_interleave_time
    gf_isom_set_interleave_time(isom_file, InterleaveTime);

    // Fuzz gf_isom_remove_sample_group
    gf_isom_remove_sample_group(isom_file, trackNumber, grouping_type);

    // Close the ISO file
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

        LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    