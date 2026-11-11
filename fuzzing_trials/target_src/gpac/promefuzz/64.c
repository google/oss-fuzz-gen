// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_check_data_reference at isom_read.c:1705:8 in isomedia.h
// gf_isom_set_interleave_time at isom_write.c:3431:8 in isomedia.h
// gf_isom_text_set_display_flags at isom_write.c:8293:8 in isomedia.h
// gf_isom_set_media_subtype at isom_write.c:6197:8 in isomedia.h
// gf_isom_set_ipod_compatible at isom_write.c:8995:8 in isomedia.h
// gf_isom_remove_sample_group at isom_write.c:7632:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

#define DUMMY_ISOFILE_SIZE 1024

static GF_ISOFile* create_dummy_isofile() {
    GF_ISOFile *isom_file = (GF_ISOFile *)malloc(DUMMY_ISOFILE_SIZE);
    if (isom_file) {
        memset(isom_file, 0, DUMMY_ISOFILE_SIZE);
    }
    return isom_file;
}

static void destroy_dummy_isofile(GF_ISOFile *isom_file) {
    if (isom_file) {
        free(isom_file);
    }
}

int LLVMFuzzerTestOneInput_64(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 7) return 0; // Ensure enough data for parameters

    GF_ISOFile *isom_file = create_dummy_isofile();
    if (!isom_file) return 0;

    u32 trackNumber = *(u32 *)Data;
    u32 sampleDescriptionIndex = *(u32 *)(Data + sizeof(u32));
    u32 interleaveTime = *(u32 *)(Data + 2 * sizeof(u32));
    u32 flags = *(u32 *)(Data + 3 * sizeof(u32));
    GF_TextFlagsMode op_type = (GF_TextFlagsMode)(*(u32 *)(Data + 4 * sizeof(u32)));
    u32 new_type = *(u32 *)(Data + 5 * sizeof(u32));
    u32 grouping_type = *(u32 *)(Data + 6 * sizeof(u32));

    // Fuzz gf_isom_check_data_reference
    gf_isom_check_data_reference(isom_file, trackNumber, sampleDescriptionIndex);

    // Fuzz gf_isom_set_interleave_time
    gf_isom_set_interleave_time(isom_file, interleaveTime);

    // Fuzz gf_isom_text_set_display_flags
    gf_isom_text_set_display_flags(isom_file, trackNumber, sampleDescriptionIndex, flags, op_type);

    // Fuzz gf_isom_set_media_subtype
    gf_isom_set_media_subtype(isom_file, trackNumber, sampleDescriptionIndex, new_type);

    // Fuzz gf_isom_set_ipod_compatible
    gf_isom_set_ipod_compatible(isom_file, trackNumber);

    // Fuzz gf_isom_remove_sample_group
    gf_isom_remove_sample_group(isom_file, trackNumber, grouping_type);

    destroy_dummy_isofile(isom_file);
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

        LLVMFuzzerTestOneInput_64(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    