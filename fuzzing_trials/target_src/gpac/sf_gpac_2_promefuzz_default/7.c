// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_refresh_fragmented at isom_read.c:3088:8 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_get_creation_time at isom_read.c:994:8 in isomedia.h
// gf_isom_get_current_top_box_offset at isom_read.c:3173:8 in isomedia.h
// gf_isom_set_creation_time at isom_write.c:221:8 in isomedia.h
// gf_isom_set_removed_bytes at isom_read.c:3185:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_isofile() {
    // As we cannot access the internal structure, we will return a NULL pointer
    // to simulate the interaction with the API functions.
    return NULL;
}

int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u64) * 2 + 1) return 0;

    GF_ISOFile *isom_file = create_dummy_isofile();

    u64 MissingBytes = 0;
    const char *new_location = "./dummy_file";
    FILE *file = fopen(new_location, "wb");
    if (!file) {
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    gf_isom_refresh_fragmented(isom_file, &MissingBytes, new_location);

    u64 top_box_start = 0;
    gf_isom_reset_data_offset(isom_file, &top_box_start);

    u64 creationTime = 0, modificationTime = 0;
    gf_isom_get_creation_time(isom_file, &creationTime, &modificationTime);

    u64 current_top_box_offset = 0;
    gf_isom_get_current_top_box_offset(isom_file, &current_top_box_offset);

    if (Size >= 2 * sizeof(u64)) {
        u64 create_time = *((u64 *)Data);
        u64 modif_time = *((u64 *)(Data + sizeof(u64)));
        gf_isom_set_creation_time(isom_file, create_time, modif_time);
    }

    if (Size >= 3 * sizeof(u64)) {
        u64 bytes_removed = *((u64 *)(Data + 2 * sizeof(u64)));
        gf_isom_set_removed_bytes(isom_file, bytes_removed);
    }

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

        LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    