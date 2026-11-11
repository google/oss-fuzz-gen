// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_enable_mfra at movie_fragments.c:3465:8 in isomedia.h
// gf_isom_freeze_order at isom_read.c:76:8 in isomedia.h
// gf_isom_update_duration at isom_write.c:8449:8 in isomedia.h
// gf_isom_remove_root_od at isom_write.c:165:8 in isomedia.h
// gf_isom_last_error at isom_read.c:46:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_isofile() {
    // Assuming GF_ISOFile can be initialized via a library function
    GF_ISOFile *isofile = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return isofile;
}

static void cleanup_isofile(GF_ISOFile *isofile) {
    if (isofile) {
        gf_isom_close(isofile);
    }
}

int LLVMFuzzerTestOneInput_2(const uint8_t *Data, size_t Size) {
    GF_ISOFile *isofile = create_dummy_isofile();
    if (!isofile) return 0;

    // Write input data to dummy file
    FILE *dummy_file = fopen("./dummy_file", "wb");
    if (!dummy_file) {
        cleanup_isofile(isofile);
        return 0;
    }
    fwrite(Data, 1, Size, dummy_file);
    fclose(dummy_file);

    // Fuzz gf_isom_enable_mfra
    gf_isom_enable_mfra(isofile);

    // Fuzz gf_isom_freeze_order
    gf_isom_freeze_order(isofile);

    // Fuzz gf_isom_update_duration
    gf_isom_update_duration(isofile);

    // Fuzz gf_isom_remove_root_od
    gf_isom_remove_root_od(isofile);

    // Fuzz gf_isom_last_error
    gf_isom_last_error(isofile);

    cleanup_isofile(isofile);
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

        LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    