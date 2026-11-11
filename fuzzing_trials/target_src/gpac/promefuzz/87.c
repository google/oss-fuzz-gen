// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_has_keep_utc_times at isom_read.c:5550:6 in isomedia.h
// gf_isom_is_inplace_rewrite at isom_write.c:9035:6 in isomedia.h
// gf_isom_keep_utc_times at isom_read.c:5543:6 in isomedia.h
// gf_isom_disable_inplace_rewrite at isom_write.c:9058:6 in isomedia.h
// gf_isom_reset_seq_num at isom_read.c:4997:6 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_delete at isom_read.c:2899:6 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static void test_gf_isom_functions(GF_ISOFile *isom_file) {
    if (!isom_file) return;

    // Test gf_isom_has_keep_utc_times
    Bool has_utc = gf_isom_has_keep_utc_times(isom_file);
    if (has_utc) {
        printf("UTC times are being kept.\n");
    }

    // Test gf_isom_is_inplace_rewrite
    Bool is_inplace = gf_isom_is_inplace_rewrite(isom_file);
    if (is_inplace) {
        printf("In-place rewriting is enabled.\n");
    }

    // Test gf_isom_keep_utc_times
    gf_isom_keep_utc_times(isom_file, GF_TRUE);

    // Test gf_isom_disable_inplace_rewrite
    gf_isom_disable_inplace_rewrite(isom_file);

    // Test gf_isom_reset_seq_num
    gf_isom_reset_seq_num(isom_file);
}

int LLVMFuzzerTestOneInput_87(const uint8_t *Data, size_t Size) {
    // Create a dummy file to simulate an ISO file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Open the dummy file as a GF_ISOFile
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) {
        return 0;
    }

    // Test the API functions
    test_gf_isom_functions(isom_file);

    // Clean up
    gf_isom_delete(isom_file);

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

        LLVMFuzzerTestOneInput_87(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    