// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_set_track_layout_info at isom_write.c:5263:8 in isomedia.h
// gf_isom_set_track_interleaving_group at isom_write.c:5868:8 in isomedia.h
// gf_isom_get_track_layout_info at isom_read.c:4116:8 in isomedia.h
// gf_isom_set_ipod_compatible at isom_write.c:8995:8 in isomedia.h
// gf_isom_set_track_matrix at isom_write.c:5254:8 in isomedia.h
// gf_isom_set_clean_aperture at isom_write.c:2132:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_iso_file() {
    // Assuming GF_ISOFile is managed internally and we cannot allocate it directly
    // Normally we would use a function from the library to create an ISOFile
    return NULL; // Placeholder for actual file creation
}

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    // Assuming there is a library function to properly clean up an ISOFile
    // Placeholder for actual cleanup
}

int LLVMFuzzerTestOneInput_120(const uint8_t *Data, size_t Size) {
    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    if (Size < sizeof(u32) * 3 + sizeof(s32) * 2 + sizeof(s16)) {
        cleanup_iso_file(iso_file);
        return 0;
    }

    u32 trackNumber = *((u32 *)Data);
    u32 width = *((u32 *)(Data + sizeof(u32)));
    u32 height = *((u32 *)(Data + 2 * sizeof(u32)));
    s32 translation_x = *((s32 *)(Data + 3 * sizeof(u32)));
    s32 translation_y = *((s32 *)(Data + 3 * sizeof(u32) + sizeof(s32)));
    s16 layer = *((s16 *)(Data + 3 * sizeof(u32) + 2 * sizeof(s32)));

    gf_isom_set_track_layout_info(iso_file, trackNumber, width, height, translation_x, translation_y, layer);

    u32 GroupID = *((u32 *)(Data + 3 * sizeof(u32) + 2 * sizeof(s32) + sizeof(s16)));
    gf_isom_set_track_interleaving_group(iso_file, trackNumber, GroupID);

    u32 out_width, out_height;
    s32 out_translation_x, out_translation_y;
    s16 out_layer;
    gf_isom_get_track_layout_info(iso_file, trackNumber, &out_width, &out_height, &out_translation_x, &out_translation_y, &out_layer);

    gf_isom_set_ipod_compatible(iso_file, trackNumber);

    s32 matrix[9];
    if (Size >= sizeof(u32) * 3 + sizeof(s32) * 2 + sizeof(s16) + sizeof(s32) * 9) {
        memcpy(matrix, Data + 3 * sizeof(u32) + 2 * sizeof(s32) + sizeof(s16) + sizeof(u32), sizeof(s32) * 9);
        gf_isom_set_track_matrix(iso_file, trackNumber, matrix);
    }

    if (Size >= sizeof(u32) * 3 + sizeof(s32) * 2 + sizeof(s16) + sizeof(u32) * 10) {
        u32 sampleDescriptionIndex = *((u32 *)(Data + 3 * sizeof(u32) + 2 * sizeof(s32) + sizeof(s16) + sizeof(u32) + sizeof(s32) * 9));
        u32 cleanApertureWidthN = *((u32 *)(Data + 3 * sizeof(u32) + 2 * sizeof(s32) + sizeof(s16) + sizeof(u32) + sizeof(s32) * 9 + sizeof(u32)));
        u32 cleanApertureWidthD = *((u32 *)(Data + 3 * sizeof(u32) + 2 * sizeof(s32) + sizeof(s16) + sizeof(u32) + sizeof(s32) * 9 + 2 * sizeof(u32)));
        u32 cleanApertureHeightN = *((u32 *)(Data + 3 * sizeof(u32) + 2 * sizeof(s32) + sizeof(s16) + sizeof(u32) + sizeof(s32) * 9 + 3 * sizeof(u32)));
        u32 cleanApertureHeightD = *((u32 *)(Data + 3 * sizeof(u32) + 2 * sizeof(s32) + sizeof(s16) + sizeof(u32) + sizeof(s32) * 9 + 4 * sizeof(u32)));
        s32 horizOffN = *((s32 *)(Data + 3 * sizeof(u32) + 2 * sizeof(s32) + sizeof(s16) + sizeof(u32) + sizeof(s32) * 9 + 5 * sizeof(u32)));
        u32 horizOffD = *((u32 *)(Data + 3 * sizeof(u32) + 2 * sizeof(s32) + sizeof(s16) + sizeof(u32) + sizeof(s32) * 9 + 5 * sizeof(u32) + sizeof(s32)));
        s32 vertOffN = *((s32 *)(Data + 3 * sizeof(u32) + 2 * sizeof(s32) + sizeof(s16) + sizeof(u32) + sizeof(s32) * 9 + 6 * sizeof(u32) + sizeof(s32)));
        u32 vertOffD = *((u32 *)(Data + 3 * sizeof(u32) + 2 * sizeof(s32) + sizeof(s16) + sizeof(u32) + sizeof(s32) * 9 + 6 * sizeof(u32) + 2 * sizeof(s32)));

        gf_isom_set_clean_aperture(iso_file, trackNumber, sampleDescriptionIndex, cleanApertureWidthN, cleanApertureWidthD, cleanApertureHeightN, cleanApertureHeightD, horizOffN, horizOffD, vertOffN, vertOffD);
    }

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

        LLVMFuzzerTestOneInput_120(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    