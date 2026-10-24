// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_last_error at isom_read.c:46:8 in isomedia.h
// gf_isom_reset_alt_brands at isom_write.c:3682:8 in isomedia.h
// gf_isom_freeze_order at isom_read.c:76:8 in isomedia.h
// gf_isom_switch_source at isom_read.c:6717:8 in isomedia.h
// gf_isom_make_interleave at isom_write.c:6051:8 in isomedia.h
// gf_isom_enable_mfra at movie_fragments.c:3462:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Since we cannot access the internal structure of GF_ISOFile, we assume a function exists to create it
    GF_ISOFile* file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    return file;
}

static void cleanup_dummy_iso_file(GF_ISOFile* file) {
    if (file) {
        gf_isom_close(file);
    }
}

int LLVMFuzzerTestOneInput_237(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    GF_ISOFile* iso_file = create_dummy_iso_file();
    if (!iso_file) {
        return 0;
    }

    // Fuzz gf_isom_last_error
    gf_isom_last_error(iso_file);

    // Fuzz gf_isom_reset_alt_brands
    gf_isom_reset_alt_brands(iso_file);

    // Fuzz gf_isom_freeze_order
    gf_isom_freeze_order(iso_file);

    // Fuzz gf_isom_switch_source
    char *url = (char *)malloc(Size + 1);
    if (url) {
        memcpy(url, Data, Size);
        url[Size] = '\0';
        gf_isom_switch_source(iso_file, url);
        free(url);
    }

    // Fuzz gf_isom_make_interleave
    Double timeInSec = (Double)Data[0];  // Simplified conversion for fuzzing
    gf_isom_make_interleave(iso_file, timeInSec);

    // Fuzz gf_isom_enable_mfra
    gf_isom_enable_mfra(iso_file);

    cleanup_dummy_iso_file(iso_file);
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

        LLVMFuzzerTestOneInput_237(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    