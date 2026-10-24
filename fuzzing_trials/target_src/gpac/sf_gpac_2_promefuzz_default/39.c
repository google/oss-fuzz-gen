// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_freeze_order at isom_read.c:76:8 in isomedia.h
// gf_isom_force_64bit_chunk_offset at isom_write.c:2788:8 in isomedia.h
// gf_isom_remove_track_from_root_od at isom_write.c:179:8 in isomedia.h
// gf_isom_set_sample_group_in_traf at isom_write.c:8656:8 in isomedia.h
// gf_isom_rewrite_track_dependencies at isom_write.c:5239:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile* initialize_iso_file() {
    GF_ISOFile* file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return file;
}

static void cleanup_iso_file(GF_ISOFile* file) {
    if (file) {
        gf_isom_close(file);
    }
}

int LLVMFuzzerTestOneInput_39(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u64) + sizeof(u32)) return 0;

    GF_ISOFile* isom_file = initialize_iso_file();
    if (!isom_file) return 0;

    u64 top_box_start = *(u64*)Data;
    u32 trackNumber = *(u32*)(Data + sizeof(u64));
    Bool set_on = (Bool)(Data[Size - 1] % 2);

    // Fuzz gf_isom_reset_data_offset
    gf_isom_reset_data_offset(isom_file, &top_box_start);
    gf_isom_reset_data_offset(isom_file, NULL);

    // Fuzz gf_isom_freeze_order
    gf_isom_freeze_order(isom_file);

    // Fuzz gf_isom_force_64bit_chunk_offset
    gf_isom_force_64bit_chunk_offset(isom_file, set_on);

    // Fuzz gf_isom_remove_track_from_root_od
    gf_isom_remove_track_from_root_od(isom_file, trackNumber);

    // Fuzz gf_isom_set_sample_group_in_traf
    gf_isom_set_sample_group_in_traf(isom_file);

    // Fuzz gf_isom_rewrite_track_dependencies
    gf_isom_rewrite_track_dependencies(isom_file, trackNumber);

    cleanup_iso_file(isom_file);
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

        LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    