// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open_progressive at isom_read.c:503:8 in isomedia.h
// gf_isom_refresh_fragmented at isom_read.c:3088:8 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_get_creation_time at isom_read.c:994:8 in isomedia.h
// gf_isom_get_current_top_box_offset at isom_read.c:3173:8 in isomedia.h
// gf_isom_set_creation_time at isom_write.c:221:8 in isomedia.h
// gf_isom_set_removed_bytes at isom_read.c:3185:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = NULL;
    u64 bytesMissing = 0;
    GF_Err err;

    // Write data to a dummy file
    write_dummy_file(Data, Size);

    // Open the ISO file progressively
    err = gf_isom_open_progressive("./dummy_file", 0, 0, 0, &isom_file, &bytesMissing);
    if (err != GF_OK || !isom_file) return 0;

    u64 missingBytes = 0;
    u64 topBoxStart = 0;
    u64 creationTime = 0;
    u64 modificationTime = 0;
    u64 currentTopBoxOffset = 0;
    const char *new_location = "./dummy_file";

    // Call the target functions with different parameters
    gf_isom_refresh_fragmented(isom_file, &missingBytes, new_location);
    gf_isom_reset_data_offset(isom_file, &topBoxStart);
    gf_isom_get_creation_time(isom_file, &creationTime, &modificationTime);
    gf_isom_get_current_top_box_offset(isom_file, &currentTopBoxOffset);
    gf_isom_set_creation_time(isom_file, creationTime, modificationTime);
    gf_isom_set_removed_bytes(isom_file, missingBytes);

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

        LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    