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
    // Since GF_ISOFile is an incomplete type, allocate memory for the maximum size
    GF_ISOFile* isom_file = (GF_ISOFile*)malloc(1024); // Allocate 1024 bytes, adjust as needed
    if (!isom_file) return NULL;
    memset(isom_file, 0, 1024);
    return isom_file;
}

static void destroy_dummy_isofile(GF_ISOFile* isom_file) {
    if (isom_file) {
        free(isom_file);
    }
}

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u64) * 3 + 1) return 0;

    GF_ISOFile* isom_file = create_dummy_isofile();
    if (!isom_file) return 0;

    u64 MissingBytes = 0;
    u64 top_box_start = 0;
    u64 creationTime = 0, modificationTime = 0;
    u64 bytes_removed = 0;
    u64 current_top_box_offset = 0;
    const char* new_location = "./dummy_file";

    // Write the first part of Data to the dummy file
    FILE *file = fopen(new_location, "wb");
    if (!file) {
        destroy_dummy_isofile(isom_file);
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Fuzz gf_isom_refresh_fragmented
    gf_isom_refresh_fragmented(isom_file, &MissingBytes, new_location);

    // Fuzz gf_isom_reset_data_offset
    gf_isom_reset_data_offset(isom_file, &top_box_start);

    // Fuzz gf_isom_get_creation_time
    gf_isom_get_creation_time(isom_file, &creationTime, &modificationTime);

    // Fuzz gf_isom_get_current_top_box_offset
    gf_isom_get_current_top_box_offset(isom_file, &current_top_box_offset);

    // Fuzz gf_isom_set_creation_time
    gf_isom_set_creation_time(isom_file, creationTime, modificationTime);

    // Fuzz gf_isom_set_removed_bytes
    gf_isom_set_removed_bytes(isom_file, bytes_removed);

    destroy_dummy_isofile(isom_file);
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

        LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    