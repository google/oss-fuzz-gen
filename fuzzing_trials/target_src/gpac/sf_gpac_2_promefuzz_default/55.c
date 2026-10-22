// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_reset_data_offset at isom_read.c:3151:8 in isomedia.h
// gf_isom_remove_track_reference at isom_write.c:5170:8 in isomedia.h
// gf_isom_force_track_duration at isom_write.c:957:8 in isomedia.h
// gf_isom_purge_samples at isom_read.c:3192:8 in isomedia.h
// gf_isom_remove_track at isom_write.c:3061:8 in isomedia.h
// gf_isom_update_edit_list_duration at isom_write.c:8473:8 in isomedia.h
// gf_isom_open at isom_read.c:527:13 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    return gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
}

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    if (iso_file) {
        gf_isom_close(iso_file);
    }
}

int LLVMFuzzerTestOneInput_55(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u64) + 2 * sizeof(u32)) {
        return 0;
    }

    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    u64 top_box_start = *(u64 *)Data;
    u32 trackNumber = *(u32 *)(Data + sizeof(u64));
    u32 ref_type = *(u32 *)(Data + sizeof(u64) + sizeof(u32));
    u64 duration = top_box_start; // Reuse top_box_start for duration
    u32 nb_samples = trackNumber; // Reuse trackNumber for nb_samples

    // Fuzz gf_isom_reset_data_offset
    gf_isom_reset_data_offset(iso_file, &top_box_start);

    // Fuzz gf_isom_remove_track_reference
    gf_isom_remove_track_reference(iso_file, trackNumber, ref_type);

    // Fuzz gf_isom_force_track_duration
    gf_isom_force_track_duration(iso_file, trackNumber, duration);

    // Fuzz gf_isom_purge_samples
    gf_isom_purge_samples(iso_file, trackNumber, nb_samples);

    // Fuzz gf_isom_remove_track
    gf_isom_remove_track(iso_file, trackNumber);

    // Fuzz gf_isom_update_edit_list_duration
    gf_isom_update_edit_list_duration(iso_file, trackNumber);

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

        LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    