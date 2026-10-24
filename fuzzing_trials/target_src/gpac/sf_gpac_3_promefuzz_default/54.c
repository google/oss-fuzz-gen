// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_set_vexu at isom_write.c:500:8 in isomedia.h
// gf_isom_set_track_priority_in_group at isom_write.c:6003:8 in isomedia.h
// gf_isom_purge_samples at isom_read.c:3192:8 in isomedia.h
// gf_isom_purge_track_reference at isom_write.c:5118:8 in isomedia.h
// gf_isom_set_track_id at isom_write.c:5195:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Since we cannot allocate GF_ISOFile directly due to incomplete type, we assume a function exists to create it.
    // This function should be part of the library, but here we just simulate the creation.
    return gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
}

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    if (iso_file) {
        gf_isom_close(iso_file);
    }
}

int LLVMFuzzerTestOneInput_54(const uint8_t *Data, size_t Size) {
    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    // Write Data to a dummy file if needed
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        cleanup_iso_file(iso_file);
        return 0;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Fuzz gf_isom_set_vexu
    if (Size >= sizeof(u32)) {
        u32 hero_eye = *((u32*)Data);
        gf_isom_set_vexu(iso_file, hero_eye);
    }

    // Fuzz gf_isom_set_track_priority_in_group
    if (Size >= sizeof(u32) * 2) {
        u32 trackNumber = *((u32*)Data);
        u32 InversePriority = *((u32*)(Data + sizeof(u32)));
        gf_isom_set_track_priority_in_group(iso_file, trackNumber, InversePriority);
    }

    // Fuzz gf_isom_purge_samples
    if (Size >= sizeof(u32) * 3) {
        u32 trackNumber = *((u32*)Data);
        u32 nb_samples = *((u32*)(Data + sizeof(u32)));
        gf_isom_purge_samples(iso_file, trackNumber, nb_samples);
    }

    // Fuzz gf_isom_purge_track_reference
    if (Size >= sizeof(u32) * 4) {
        u32 trackNumber = *((u32*)Data);
        gf_isom_purge_track_reference(iso_file, trackNumber);
    }

    // Fuzz gf_isom_set_track_id
    if (Size >= sizeof(u32) * 5) {
        u32 trackNumber = *((u32*)Data);
        GF_ISOTrackID trackID = *((GF_ISOTrackID*)(Data + sizeof(u32)));
        gf_isom_set_track_id(iso_file, trackNumber, trackID);
    }

    // Close the file
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

        LLVMFuzzerTestOneInput_54(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    