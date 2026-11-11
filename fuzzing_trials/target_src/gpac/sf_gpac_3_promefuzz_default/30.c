// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open_progressive at isom_read.c:503:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_refresh_fragmented at isom_read.c:3088:8 in isomedia.h
// gf_isom_get_current_top_box_offset at isom_read.c:3173:8 in isomedia.h
// gf_isom_set_creation_time at isom_write.c:221:8 in isomedia.h
// gf_isom_get_creation_time at isom_read.c:994:8 in isomedia.h
// gf_isom_set_removed_bytes at isom_read.c:3185:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "isomedia.h"

static GF_ISOFile* initialize_iso_file() {
    GF_ISOFile *iso_file = NULL;
    u64 bytes_missing = 0;
    const char *dummy_file = "./dummy_file";

    // Create a dummy file to avoid NULL pointer dereference
    FILE *file = fopen(dummy_file, "wb");
    if (file) {
        fclose(file);
    }

    gf_isom_open_progressive(dummy_file, 0, 0, 0, &iso_file, &bytes_missing);
    return iso_file;
}

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    if (iso_file) {
        gf_isom_close(iso_file);
    }
}

int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u64) * 2 + 1) return 0;

    GF_ISOFile *iso_file = initialize_iso_file();
    if (!iso_file) return 0;

    u64 missing_bytes = 0;
    u64 creation_time = 0, modification_time = 0;
    u64 current_top_box_offset = 0;
    u64 bytes_removed = 0;
    const char *new_location = "./dummy_file";

    // Fuzz gf_isom_refresh_fragmented
    gf_isom_refresh_fragmented(iso_file, &missing_bytes, new_location);

    // Fuzz gf_isom_get_current_top_box_offset
    gf_isom_get_current_top_box_offset(iso_file, &current_top_box_offset);

    // Fuzz gf_isom_set_creation_time
    if (Size >= sizeof(u64) * 2) {
        memcpy(&creation_time, Data, sizeof(u64));
        memcpy(&modification_time, Data + sizeof(u64), sizeof(u64));
        gf_isom_set_creation_time(iso_file, creation_time, modification_time);
    }

    // Fuzz gf_isom_get_creation_time
    gf_isom_get_creation_time(iso_file, &creation_time, &modification_time);

    // Fuzz gf_isom_set_removed_bytes
    if (Size >= sizeof(u64)) {
        memcpy(&bytes_removed, Data, sizeof(u64));
        gf_isom_set_removed_bytes(iso_file, bytes_removed);
    }

    cleanup_iso_file(iso_file);

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

        LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    