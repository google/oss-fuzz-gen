// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
// gf_isom_remove_track at isom_write.c:2942:8 in isomedia.h
// gf_isom_set_sample_rap_group at isom_write.c:7715:8 in isomedia.h
// gf_isom_vvc_set_inband_config at avc_ext.c:2427:8 in isomedia.h
// gf_isom_fragment_set_sample_rap_group at isom_write.c:7720:8 in isomedia.h
// gf_isom_set_fragment_original_duration at movie_fragments.c:3171:8 in isomedia.h
// gf_isom_add_sample_group_info at isom_write.c:7555:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "isomedia.h"

#define DUMMY_FILE "./dummy_file"

static GF_ISOFile* create_dummy_iso_file() {
    // Create a dummy file on disk for testing
    FILE *file = fopen(DUMMY_FILE, "wb");
    if (file) {
        fwrite("dummy", 1, 5, file);
        fclose(file);
    }

    // Open the file using gpac API to get a GF_ISOFile object
    GF_ISOFile *iso_file = gf_isom_open(DUMMY_FILE, GF_ISOM_OPEN_WRITE, NULL);
    return iso_file;
}

static void cleanup_iso_file(GF_ISOFile *iso_file) {
    if (!iso_file) return;
    gf_isom_close(iso_file);
    remove(DUMMY_FILE);
}

int LLVMFuzzerTestOneInput_95(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32) * 3 + sizeof(Bool)) return 0;

    GF_ISOFile *iso_file = create_dummy_iso_file();
    if (!iso_file) return 0;

    u32 trackNumber = *((u32 *)Data);
    u32 sampleNumber = *((u32 *)(Data + sizeof(u32)));
    Bool is_rap = *((Bool *)(Data + sizeof(u32) * 2));
    u32 num_leading_samples = *((u32 *)(Data + sizeof(u32) * 2 + sizeof(Bool)));

    // Fuzz gf_isom_remove_track
    gf_isom_remove_track(iso_file, trackNumber);

    // Fuzz gf_isom_set_sample_rap_group
    gf_isom_set_sample_rap_group(iso_file, trackNumber, sampleNumber, is_rap, num_leading_samples);

    // Fuzz gf_isom_vvc_set_inband_config
    gf_isom_vvc_set_inband_config(iso_file, trackNumber, sampleNumber, is_rap);

    // Fuzz gf_isom_fragment_set_sample_rap_group
    gf_isom_fragment_set_sample_rap_group(iso_file, trackNumber, sampleNumber, is_rap, num_leading_samples);

    // Fuzz gf_isom_set_fragment_original_duration
    gf_isom_set_fragment_original_duration(iso_file, trackNumber, sampleNumber, num_leading_samples);

    // Fuzz gf_isom_add_sample_group_info
    gf_isom_add_sample_group_info(iso_file, trackNumber, sampleNumber, (void *)Data, Size, is_rap, NULL);

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

        LLVMFuzzerTestOneInput_95(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    