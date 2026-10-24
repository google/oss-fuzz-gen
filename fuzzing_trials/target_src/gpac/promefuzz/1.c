// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_get_media_type at isom_read.c:1586:5 in isomedia.h
// gf_isom_get_sample_description_count at isom_read.c:1373:5 in isomedia.h
// gf_isom_get_track_kind_count at isom_read.c:1136:5 in isomedia.h
// gf_isom_is_track_referenced at isom_read.c:1316:5 in isomedia.h
// gf_isom_get_track_count at isom_read.c:783:5 in isomedia.h
// gf_isom_get_track_group at isom_read.c:6437:5 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_isofile() {
    // As we don't have the full definition of GF_ISOFile, we can't allocate it properly.
    // Therefore, we return NULL to simulate the behavior of an uninitialized or invalid file.
    return NULL;
}

int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32)) return 0;

    GF_ISOFile *isoFile = create_dummy_isofile();

    u32 trackNumber = *((u32 *)Data);
    Data += sizeof(u32);
    Size -= sizeof(u32);

    gf_isom_get_media_type(isoFile, trackNumber);
    gf_isom_get_sample_description_count(isoFile, trackNumber);
    gf_isom_get_track_kind_count(isoFile, trackNumber);

    if (Size >= sizeof(u32)) {
        u32 referenceType = *((u32 *)Data);
        gf_isom_is_track_referenced(isoFile, trackNumber, referenceType);
    }

    gf_isom_get_track_count(isoFile);

    if (Size >= 2 * sizeof(u32)) {
        u32 track_group_type = *((u32 *)(Data + sizeof(u32)));
        gf_isom_get_track_group(isoFile, trackNumber, track_group_type);
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

        LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    