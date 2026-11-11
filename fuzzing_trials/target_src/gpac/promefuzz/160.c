// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_get_brand_info at isom_read.c:2631:8 in isomedia.h
// gf_isom_get_alternate_brand at isom_read.c:2648:8 in isomedia.h
// gf_isom_refresh_size_info at stbl_write.c:2299:8 in isomedia.h
// gf_isom_set_root_od_id at isom_write.c:540:8 in isomedia.h
// gf_isom_set_nalu_length_field at isom_write.c:8502:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

#define DUMMY_FILE_PATH "./dummy_file"

static GF_ISOFile* create_dummy_iso_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen(DUMMY_FILE_PATH, "wb");
    if (!file) return NULL;
    fwrite(Data, 1, Size, file);
    fclose(file);
    
    GF_ISOFile *iso_file = gf_isom_open(DUMMY_FILE_PATH, GF_ISOM_OPEN_READ, NULL);
    return iso_file;
}

int LLVMFuzzerTestOneInput_160(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0; // Ensure there's enough data to work with

    GF_ISOFile *iso_file = create_dummy_iso_file(Data, Size);
    if (!iso_file) return 0;

    u32 brand = 0, minorVersion = 0, AlternateBrandsCount = 0;
    gf_isom_get_brand_info(iso_file, &brand, &minorVersion, &AlternateBrandsCount);

    if (AlternateBrandsCount > 0) {
        for (u32 i = 1; i <= AlternateBrandsCount; ++i) {
            u32 alt_brand = 0;
            gf_isom_get_alternate_brand(iso_file, i, &alt_brand);
        }
    }

    if (Size > 8) {
        u32 trackNumber = *(u32 *)(Data + 4);
        gf_isom_refresh_size_info(iso_file, trackNumber);
    }

    if (Size > 12) {
        u32 OD_ID = *(u32 *)(Data + 8);
        gf_isom_set_root_od_id(iso_file, OD_ID);
    }

    if (Size > 16) {
        u32 trackNumber = *(u32 *)(Data + 12);
        u32 sampleDescriptionIndex = *(u32 *)(Data + 16);
        u32 nalu_size_length = *(u32 *)(Data + 20);
        gf_isom_set_nalu_length_field(iso_file, trackNumber, sampleDescriptionIndex, nalu_size_length);
    }

    gf_isom_close(iso_file);
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

        LLVMFuzzerTestOneInput_160(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    