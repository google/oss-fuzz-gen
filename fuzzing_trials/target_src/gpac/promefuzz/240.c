// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_get_missing_bytes at isom_read.c:2482:5 in isomedia.h
// gf_isom_get_media_original_duration at isom_read.c:1448:5 in isomedia.h
// gf_isom_get_current_tfdt at isom_read.c:5822:5 in isomedia.h
// gf_isom_get_track_duration at isom_read.c:1076:5 in isomedia.h
// gf_isom_get_track_magic at isom_read.c:6160:5 in isomedia.h
// gf_isom_get_media_data_size at isom_read.c:4131:5 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_240(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32)) {
        return 0;
    }

    // Prepare the environment
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) {
        return 0;
    }

    u32 trackNumber = *(u32 *)(Data + Size - sizeof(u32));

    // Write dummy data to the file
    write_dummy_file(Data, Size - sizeof(u32));

    // Invoke target API functions
    u64 missing_bytes = gf_isom_get_missing_bytes(isom_file, trackNumber);
    u64 original_duration = gf_isom_get_media_original_duration(isom_file, trackNumber);
    u64 current_tfdt = gf_isom_get_current_tfdt(isom_file, trackNumber);
    u64 track_duration = gf_isom_get_track_duration(isom_file, trackNumber);
    u64 track_magic = gf_isom_get_track_magic(isom_file, trackNumber);
    u64 media_data_size = gf_isom_get_media_data_size(isom_file, trackNumber);

    // Cleanup
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

        LLVMFuzzerTestOneInput_240(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    