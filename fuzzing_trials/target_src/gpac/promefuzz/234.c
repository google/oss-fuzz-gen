// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_last_error at isom_read.c:46:8 in isomedia.h
// gf_isom_reset_alt_brands at isom_write.c:3682:8 in isomedia.h
// gf_isom_freeze_order at isom_read.c:76:8 in isomedia.h
// gf_isom_switch_source at isom_read.c:6717:8 in isomedia.h
// gf_isom_make_interleave at isom_write.c:6051:8 in isomedia.h
// gf_isom_enable_mfra at movie_fragments.c:3462:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

// Assuming a reasonable size for the GF_ISOFile structure
#define ISOFILE_STRUCT_SIZE 1024

static GF_ISOFile* create_initialized_isofile() {
    GF_ISOFile *file = (GF_ISOFile *)malloc(ISOFILE_STRUCT_SIZE);
    if (!file) return NULL;
    memset(file, 0, ISOFILE_STRUCT_SIZE);
    return file;
}

static void free_initialized_isofile(GF_ISOFile *file) {
    if (!file) return;
    free(file);
}

int LLVMFuzzerTestOneInput_234(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    GF_ISOFile* isofile = create_initialized_isofile();
    if (!isofile) return 0;

    // Fuzz gf_isom_last_error
    gf_isom_last_error(isofile);

    // Fuzz gf_isom_reset_alt_brands
    gf_isom_reset_alt_brands(isofile);

    // Fuzz gf_isom_freeze_order
    gf_isom_freeze_order(isofile);

    // Fuzz gf_isom_switch_source
    char url[256];
    snprintf(url, sizeof(url), "gmem://%.*s", (int)Size, Data);
    gf_isom_switch_source(isofile, url);

    // Fuzz gf_isom_make_interleave
    Double interleave_time = (Double)(Data[0] % 10);
    gf_isom_make_interleave(isofile, interleave_time);

    // Fuzz gf_isom_enable_mfra
    gf_isom_enable_mfra(isofile);

    free_initialized_isofile(isofile);
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

        LLVMFuzzerTestOneInput_234(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    