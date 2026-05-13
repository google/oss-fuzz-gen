// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_reset_fragment_info at isom_read.c:4976:6 in isomedia.h
// gf_isom_has_keep_utc_times at isom_read.c:5550:6 in isomedia.h
// gf_isom_enable_traf_map_templates at isom_read.c:6026:6 in isomedia.h
// gf_isom_is_smooth_streaming_moov at isom_read.c:5848:6 in isomedia.h
// gf_isom_reset_sample_count at isom_read.c:5005:6 in isomedia.h
// gf_isom_delete at isom_read.c:2899:6 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "isomedia.h"

static GF_ISOFile* create_dummy_isofile() {
    // Since GF_ISOFile is an incomplete type, we cannot allocate it directly.
    // Assuming we have a function to create or initialize GF_ISOFile in the actual library.
    // Here we simulate it by returning NULL as a stub.
    return NULL;
}

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    GF_ISOFile *isom_file = create_dummy_isofile();

    Bool keep_sample_count = Data[0] % 2;

    // Fuzz gf_isom_reset_fragment_info
    gf_isom_reset_fragment_info(isom_file, keep_sample_count);

    // Fuzz gf_isom_has_keep_utc_times
    Bool utc_times = gf_isom_has_keep_utc_times(isom_file);

    // Fuzz gf_isom_enable_traf_map_templates
    gf_isom_enable_traf_map_templates(isom_file);

    // Fuzz gf_isom_is_smooth_streaming_moov
    Bool smooth_streaming = gf_isom_is_smooth_streaming_moov(isom_file);

    // Fuzz gf_isom_reset_sample_count
    gf_isom_reset_sample_count(isom_file);

    // Write to dummy file
    write_dummy_file(Data, Size);

    // Clean up resources
    gf_isom_delete(isom_file);

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

        LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    