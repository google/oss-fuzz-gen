// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_svc_config_del at avc_ext.c:1818:8 in isomedia.h
// gf_isom_add_desc_to_root_od at isom_write.c:413:8 in isomedia.h
// gf_isom_remove_cenc_senc_box at drm_sample.c:996:8 in isomedia.h
// gf_isom_remove_track_from_root_od at isom_write.c:179:8 in isomedia.h
// gf_isom_set_storage_mode at isom_write.c:2755:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_isofile() {
    GF_ISOFile *file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, "/tmp");
    return file;
}

static GF_Descriptor* create_dummy_descriptor() {
    // Allocate a larger memory block to simulate a real descriptor
    GF_Descriptor *desc = (GF_Descriptor *)malloc(sizeof(GF_Descriptor) + 100);
    if (!desc) return NULL;
    // Initialize descriptor with dummy values if needed
    memset(desc, 0, sizeof(GF_Descriptor) + 100);
    return desc;
}

int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 2) return 0;

    GF_ISOFile *isom_file = create_dummy_isofile();
    if (!isom_file) return 0;

    u32 trackNumber = *(u32 *)Data;
    u32 sampleDescriptionIndex = *(u32 *)(Data + sizeof(u32));
    GF_Descriptor *theDesc = create_dummy_descriptor();

    if (theDesc) {
        // Fuzz gf_isom_svc_config_del
        gf_isom_svc_config_del(isom_file, trackNumber, sampleDescriptionIndex);

        // Fuzz gf_isom_add_desc_to_root_od
        gf_isom_add_desc_to_root_od(isom_file, theDesc);

        // Fuzz gf_isom_remove_cenc_senc_box
        gf_isom_remove_cenc_senc_box(isom_file, trackNumber);

        // Fuzz gf_isom_remove_track_from_root_od
        gf_isom_remove_track_from_root_od(isom_file, trackNumber);

        // Fuzz gf_isom_set_storage_mode
        gf_isom_set_storage_mode(isom_file, (GF_ISOStorageMode)(trackNumber % 3));

        // Cleanup
        free(theDesc);
    }

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

        LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    