// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_refresh_fragmented at isom_read.c:3088:8 in isomedia.h
// gf_isom_get_current_top_box_offset at isom_read.c:3173:8 in isomedia.h
// gf_isom_set_creation_time at isom_write.c:221:8 in isomedia.h
// gf_isom_get_creation_time at isom_read.c:994:8 in isomedia.h
// gf_isom_set_removed_bytes at isom_read.c:3185:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "isomedia.h"

int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    // Create dummy file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        gf_isom_close(isom_file);
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    u64 MissingBytes = 0;
    const char *new_location = NULL;
    u64 current_top_box_offset = 0;
    u64 create_time = 0;
    u64 modif_time = 0;
    u64 creationTime = 0;
    u64 modificationTime = 0;
    u64 bytes_removed = 0;

    // Call the target functions with fuzzing inputs
    gf_isom_refresh_fragmented(isom_file, &MissingBytes, new_location);
    gf_isom_get_current_top_box_offset(isom_file, &current_top_box_offset);
    gf_isom_set_creation_time(isom_file, create_time, modif_time);
    gf_isom_get_creation_time(isom_file, &creationTime, &modificationTime);
    gf_isom_set_removed_bytes(isom_file, bytes_removed);

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

        LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    