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

static GF_ISOFile* create_iso_file() {
    GF_ISOFile *file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
    return file;
}

static void destroy_iso_file(GF_ISOFile *file) {
    if (file) {
        gf_isom_close(file);
    }
}

int LLVMFuzzerTestOneInput_62(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u64) + sizeof(u32) * 3 + sizeof(u64)) return 0;

    GF_ISOFile *isom_file = create_iso_file();
    if (!isom_file) return 0;

    u64 top_box_start = *(u64 *)Data;
    u32 trackNumber = *(u32 *)(Data + sizeof(u64));
    u32 ref_type = *(u32 *)(Data + sizeof(u64) + sizeof(u32));
    u64 duration = *(u64 *)(Data + sizeof(u64) + sizeof(u32) * 2);
    u32 nb_samples = *(u32 *)(Data + sizeof(u64) + sizeof(u32) * 2 + sizeof(u64));

    gf_isom_reset_data_offset(isom_file, &top_box_start);
    gf_isom_remove_track_reference(isom_file, trackNumber, ref_type);
    gf_isom_force_track_duration(isom_file, trackNumber, duration);
    gf_isom_purge_samples(isom_file, trackNumber, nb_samples);
    gf_isom_remove_track(isom_file, trackNumber);
    gf_isom_update_edit_list_duration(isom_file, trackNumber);

    destroy_iso_file(isom_file);
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

        LLVMFuzzerTestOneInput_62(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    