// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_purge_samples at isom_read.c:3192:8 in isomedia.h
// gf_isom_set_vexu at isom_write.c:500:8 in isomedia.h
// gf_isom_purge_track_reference at isom_write.c:5118:8 in isomedia.h
// gf_isom_set_byte_offset at isom_read.c:5910:8 in isomedia.h
// gf_isom_set_track_id at isom_write.c:5195:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

static GF_ISOFile *initialize_iso_file() {
    // Adjusted to include the third parameter for gf_isom_open
    return gf_isom_open("./dummy_file", GF_ISOM_OPEN_WRITE, NULL);
}

static void cleanup_iso_file(GF_ISOFile *isom_file) {
    if (isom_file) {
        // Use the API function to properly close and clean up the ISO file
        gf_isom_close(isom_file);
    }
}

int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3 + sizeof(s64)) return 0;

    GF_ISOFile *isom_file = initialize_iso_file();
    if (!isom_file) return 0;

    // Extract parameters from the input data
    u32 trackNumber = *((u32 *)Data);
    u32 nb_samples = *((u32 *)(Data + sizeof(u32)));
    u32 hero_eye = *((u32 *)(Data + 2 * sizeof(u32)));
    s64 byte_offset = *((s64 *)(Data + 3 * sizeof(u32)));

    // Create a dummy file if needed
    FILE *dummy_file = fopen("./dummy_file", "wb");
    if (dummy_file) {
        fwrite(Data, 1, Size, dummy_file);
        fclose(dummy_file);
    }

    // Call the target functions with extracted parameters
    gf_isom_purge_samples(isom_file, trackNumber, nb_samples);
    gf_isom_set_vexu(isom_file, hero_eye);
    gf_isom_purge_track_reference(isom_file, trackNumber);
    gf_isom_set_byte_offset(isom_file, byte_offset);
    gf_isom_set_track_id(isom_file, trackNumber, trackNumber + 1); // Just a simple increment for new ID

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

        LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    