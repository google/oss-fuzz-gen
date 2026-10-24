// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_reset_sample_count at isom_read.c:5005:6 in isomedia.h
// gf_isom_enable_traf_map_templates at isom_read.c:6026:6 in isomedia.h
// gf_isom_disable_inplace_rewrite at isom_write.c:9177:6 in isomedia.h
// gf_isom_keep_utc_times at isom_read.c:5543:6 in isomedia.h
// gf_isom_has_keep_utc_times at isom_read.c:5550:6 in isomedia.h
// gf_isom_needs_layer_reconstruction at isom_read.c:5516:6 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

#define DUMMY_FILE_PATH "./dummy_file"
#define TMP_DIR_PATH "/tmp"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen(DUMMY_FILE_PATH, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    // Write the input data to a dummy file
    write_dummy_file(Data, Size);

    // Allocate memory for GF_ISOFile dynamically
    GF_ISOFile *isom_file = gf_isom_open(DUMMY_FILE_PATH, GF_ISOM_OPEN_READ, TMP_DIR_PATH);
    if (!isom_file) {
        return 0;
    }

    // Call the target functions with the initialized structure
    gf_isom_reset_sample_count(isom_file);
    gf_isom_keep_utc_times(isom_file, GF_TRUE);
    gf_isom_keep_utc_times(isom_file, GF_FALSE);

    Bool has_utc = gf_isom_has_keep_utc_times(isom_file);

    Bool needs_reconstruction = gf_isom_needs_layer_reconstruction(isom_file);

    gf_isom_enable_traf_map_templates(isom_file);
    gf_isom_disable_inplace_rewrite(isom_file);

    // Close the ISO file and free resources
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

        LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    