// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_remove_track_reference at isom_write.c:5170:8 in isomedia.h
// gf_isom_force_track_duration at isom_write.c:957:8 in isomedia.h
// gf_isom_purge_samples at isom_read.c:3192:8 in isomedia.h
// gf_isom_remove_track at isom_write.c:3061:8 in isomedia.h
// gf_isom_update_edit_list_duration at isom_write.c:8473:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

// Define a dummy structure with the same size as GF_ISOFile for allocation
typedef struct {
    char dummy[256]; // Adjust size as necessary
} DummyGF_ISOFile;

static GF_ISOFile* create_dummy_isofile() {
    // Allocate memory for the DummyGF_ISOFile structure
    DummyGF_ISOFile *dummy_isom_file = (DummyGF_ISOFile*)malloc(sizeof(DummyGF_ISOFile));
    if (!dummy_isom_file) return NULL;
    memset(dummy_isom_file, 0, sizeof(DummyGF_ISOFile));
    return (GF_ISOFile*)dummy_isom_file;
}

int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u64)) return 0;

    GF_ISOFile *isom_file = create_dummy_isofile();
    if (!isom_file) return 0;

    u64 top_box_start = 0;
    if (Size >= sizeof(u64)) {
        memcpy(&top_box_start, Data, sizeof(u64));
        Data += sizeof(u64);
        Size -= sizeof(u64);
    }

    // Fuzz gf_isom_reset_data_offset
    gf_isom_reset_data_offset(isom_file, &top_box_start);

    // Fuzz gf_isom_remove_track_reference
    if (Size >= sizeof(u32) * 2) {
        u32 trackNumber = 0;
        u32 ref_type = 0;
        memcpy(&trackNumber, Data, sizeof(u32));
        memcpy(&ref_type, Data + sizeof(u32), sizeof(u32));
        gf_isom_remove_track_reference(isom_file, trackNumber, ref_type);
    }

    // Fuzz gf_isom_force_track_duration
    if (Size >= sizeof(u32) + sizeof(u64)) {
        u32 trackNumber = 0;
        u64 duration = 0;
        memcpy(&trackNumber, Data, sizeof(u32));
        memcpy(&duration, Data + sizeof(u32), sizeof(u64));
        gf_isom_force_track_duration(isom_file, trackNumber, duration);
    }

    // Fuzz gf_isom_purge_samples
    if (Size >= sizeof(u32) * 2) {
        u32 trackNumber = 0;
        u32 nb_samples = 0;
        memcpy(&trackNumber, Data, sizeof(u32));
        memcpy(&nb_samples, Data + sizeof(u32), sizeof(u32));
        gf_isom_purge_samples(isom_file, trackNumber, nb_samples);
    }

    // Fuzz gf_isom_remove_track
    if (Size >= sizeof(u32)) {
        u32 trackNumber = 0;
        memcpy(&trackNumber, Data, sizeof(u32));
        gf_isom_remove_track(isom_file, trackNumber);
    }

    // Fuzz gf_isom_update_edit_list_duration
    if (Size >= sizeof(u32)) {
        u32 trackNumber = 0;
        memcpy(&trackNumber, Data, sizeof(u32));
        gf_isom_update_edit_list_duration(isom_file, trackNumber);
    }

    free(isom_file);
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

        LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    