// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_reset_fragment_info at isom_read.c:4976:6 in isomedia.h
// gf_isom_flush_fragments at movie_fragments.c:1469:8 in isomedia.h
// gf_isom_reset_sample_count at isom_read.c:5005:6 in isomedia.h
// gf_isom_reset_tables at isom_read.c:3407:8 in isomedia.h
// gf_isom_is_JPEG2000 at isom_read.c:4270:6 in isomedia.h
// gf_isom_is_inplace_rewrite at isom_write.c:9154:6 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "isomedia.h"

#define DUMMY_FILE_PATH "./dummy_file"

static GF_ISOFile* create_dummy_isofile() {
    GF_ISOFile *isom_file = gf_isom_open(DUMMY_FILE_PATH, GF_ISOM_OPEN_WRITE, NULL);
    return isom_file;
}

static void cleanup_dummy_isofile(GF_ISOFile *isom_file) {
    if (isom_file) {
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there's at least some data to use

    // Create a dummy file for operations that require file access
    FILE *dummy_file = fopen(DUMMY_FILE_PATH, "wb");
    if (!dummy_file) return 0;
    fwrite(Data, 1, Size, dummy_file);
    fclose(dummy_file);

    GF_ISOFile *isom_file = create_dummy_isofile();
    if (!isom_file) {
        remove(DUMMY_FILE_PATH);
        return 0;
    }

    // Use the first byte of data to decide boolean values
    Bool bool_value = (Data[0] % 2) == 0 ? GF_TRUE : GF_FALSE;

    // Fuzz gf_isom_reset_fragment_info
    gf_isom_reset_fragment_info(isom_file, bool_value);

    // Fuzz gf_isom_flush_fragments
    gf_isom_flush_fragments(isom_file, bool_value);

    // Fuzz gf_isom_reset_sample_count
    gf_isom_reset_sample_count(isom_file);

    // Fuzz gf_isom_reset_tables
    gf_isom_reset_tables(isom_file, bool_value);

    // Fuzz gf_isom_is_JPEG2000
    Bool is_jpeg2000 = gf_isom_is_JPEG2000(isom_file);

    // Fuzz gf_isom_is_inplace_rewrite
    Bool is_inplace_rewrite = gf_isom_is_inplace_rewrite(isom_file);

    // Cleanup
    cleanup_dummy_isofile(isom_file);

    // Remove the dummy file
    remove(DUMMY_FILE_PATH);

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

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    