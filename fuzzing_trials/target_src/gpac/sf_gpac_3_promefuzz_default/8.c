// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_enable_mfra at movie_fragments.c:3465:8 in isomedia.h
// gf_isom_last_error at isom_read.c:46:8 in isomedia.h
// gf_isom_freeze_order at isom_read.c:76:8 in isomedia.h
// gf_isom_last_error at isom_read.c:46:8 in isomedia.h
// gf_isom_update_duration at isom_write.c:8449:8 in isomedia.h
// gf_isom_last_error at isom_read.c:46:8 in isomedia.h
// gf_isom_remove_root_od at isom_write.c:165:8 in isomedia.h
// gf_isom_last_error at isom_read.c:46:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isom_file = NULL;
    GF_Err err;

    // Step 1: Write data to a dummy file
    write_dummy_file(Data, Size);

    // Step 2: Open the dummy file as a GF_ISOFile
    if (Size > 0) {
        isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    }

    if (isom_file) {
        // Step 3: Invoke the target functions with the opened file

        // Test gf_isom_enable_mfra
        err = gf_isom_enable_mfra(isom_file);
        if (err != GF_OK) {
            gf_isom_last_error(isom_file);
        }

        // Test gf_isom_freeze_order
        err = gf_isom_freeze_order(isom_file);
        if (err != GF_OK) {
            gf_isom_last_error(isom_file);
        }

        // Test gf_isom_update_duration
        err = gf_isom_update_duration(isom_file);
        if (err != GF_OK) {
            gf_isom_last_error(isom_file);
        }

        // Test gf_isom_remove_root_od
        err = gf_isom_remove_root_od(isom_file);
        if (err != GF_OK) {
            gf_isom_last_error(isom_file);
        }

        // Close the ISO file
        gf_isom_close(isom_file);
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

        LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    