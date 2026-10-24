// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_evte_config_new at sample_descs.c:1846:8 in isomedia.h
// gf_isom_set_root_od_id at isom_write.c:540:8 in isomedia.h
// gf_isom_svc_config_del at avc_ext.c:1818:8 in isomedia.h
// gf_isom_remove_track_from_root_od at isom_write.c:179:8 in isomedia.h
// gf_isom_set_extraction_slc at isom_write.c:5927:8 in isomedia.h
// gf_isom_get_reference_ID at isom_read.c:1270:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Create a dummy file for the purpose of fuzzing
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return NULL;
    fclose(file);

    // Open the ISO file using the GPAC API
    GF_ISOFile *iso_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return iso_file;
}

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    if (iso_file) {
        gf_isom_close(iso_file);
    }
}

int LLVMFuzzerTestOneInput_249(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 5) return 0; // Ensure enough data for all parameters

    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    u32 trackNumber = *(u32*)Data;
    u32 outDescriptionIndex = 0;
    u32 sampleDescriptionIndex = *(u32*)(Data + sizeof(u32));
    u32 OD_ID = *(u32*)(Data + 2 * sizeof(u32));
    u32 referenceType = *(u32*)(Data + 3 * sizeof(u32));
    u32 referenceIndex = *(u32*)(Data + 4 * sizeof(u32));
    GF_ISOTrackID refTrackID = 0;
    GF_SLConfig *slConfig = NULL;

    // Fuzz gf_isom_evte_config_new
    gf_isom_evte_config_new(iso_file, trackNumber, &outDescriptionIndex);

    // Fuzz gf_isom_set_root_od_id
    gf_isom_set_root_od_id(iso_file, OD_ID);

    // Fuzz gf_isom_svc_config_del
    gf_isom_svc_config_del(iso_file, trackNumber, sampleDescriptionIndex);

    // Fuzz gf_isom_remove_track_from_root_od
    gf_isom_remove_track_from_root_od(iso_file, trackNumber);

    // Fuzz gf_isom_set_extraction_slc
    gf_isom_set_extraction_slc(iso_file, trackNumber, sampleDescriptionIndex, slConfig);

    // Fuzz gf_isom_get_reference_ID
    gf_isom_get_reference_ID(iso_file, trackNumber, referenceType, referenceIndex, &refTrackID);

    cleanup_iso_file(iso_file);
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

        LLVMFuzzerTestOneInput_249(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    