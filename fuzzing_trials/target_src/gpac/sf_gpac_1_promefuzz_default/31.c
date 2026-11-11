// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_get_first_mdat_start at isom_read.c:4163:5 in isomedia.h
// gf_isom_reset_sample_count at isom_read.c:5005:6 in isomedia.h
// gf_isom_get_media_data_size at isom_read.c:4131:5 in isomedia.h
// gf_isom_get_duration at isom_read.c:971:5 in isomedia.h
// gf_isom_estimate_size at isom_write.c:5902:5 in isomedia.h
// gf_isom_get_creation_time at isom_read.c:994:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile* open_dummy_iso_file() {
    // Simulate opening an ISO file by allocating memory for GF_ISOFile
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return isom_file;
}

static void close_dummy_iso_file(GF_ISOFile *isom_file) {
    if (!isom_file) return;
    gf_isom_close(isom_file);
}

int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32)) return 0;

    // Write the input data to a dummy file
    FILE *dummy_file = fopen("./dummy_file", "wb");
    if (!dummy_file) return 0;
    fwrite(Data, 1, Size, dummy_file);
    fclose(dummy_file);

    GF_ISOFile *isom_file = open_dummy_iso_file();
    if (!isom_file) return 0;

    // Fuzz gf_isom_get_first_mdat_start
    u64 mdat_start = gf_isom_get_first_mdat_start(isom_file);

    // Fuzz gf_isom_reset_sample_count
    gf_isom_reset_sample_count(isom_file);

    // Fuzz gf_isom_get_media_data_size
    u32 trackNumber = *(u32 *)Data;
    u64 media_data_size = gf_isom_get_media_data_size(isom_file, trackNumber);

    // Fuzz gf_isom_get_duration
    u64 duration = gf_isom_get_duration(isom_file);

    // Fuzz gf_isom_estimate_size
    u64 estimated_size = gf_isom_estimate_size(isom_file);

    // Fuzz gf_isom_get_creation_time
    u64 creationTime = 0, modificationTime = 0;
    GF_Err creation_time_err = gf_isom_get_creation_time(isom_file, &creationTime, &modificationTime);

    // Cleanup
    close_dummy_iso_file(isom_file);

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
    