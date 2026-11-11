// This fuzz driver is generated for library gpac, aiming to fuzz the following functions:
// gf_isom_open at isom_read.c:527:13 in isomedia.h
// gf_isom_has_sample_dependency at isom_read.c:1904:6 in isomedia.h
// gf_isom_reset_fragment_info at isom_read.c:4976:6 in isomedia.h
// gf_isom_has_padding_bits at isom_read.c:2680:6 in isomedia.h
// gf_isom_reset_sample_count at isom_read.c:5005:6 in isomedia.h
// gf_isom_is_JPEG2000 at isom_read.c:4270:6 in isomedia.h
// gf_isom_set_sample_rap_group at isom_write.c:7834:8 in isomedia.h
// gf_isom_close at isom_read.c:629:8 in isomedia.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "isomedia.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(u32)) return 0;

    // Prepare the environment
    GF_ISOFile *isom_file = gf_isom_open("./dummy_file", GF_ISOM_OPEN_READ, NULL);
    if (!isom_file) return 0;

    u32 trackNumber = *((u32 *)Data);
    Data += sizeof(u32);
    Size -= sizeof(u32);

    // Invoke gf_isom_has_sample_dependency
    Bool has_dependency = gf_isom_has_sample_dependency(isom_file, trackNumber);

    // Invoke gf_isom_reset_fragment_info
    Bool keep_sample_count = (Size > 0) ? (Data[0] % 2) : GF_FALSE;
    gf_isom_reset_fragment_info(isom_file, keep_sample_count);

    // Invoke gf_isom_has_padding_bits
    Bool has_padding_bits = gf_isom_has_padding_bits(isom_file, trackNumber);

    // Invoke gf_isom_reset_sample_count
    gf_isom_reset_sample_count(isom_file);

    // Invoke gf_isom_is_JPEG2000
    Bool is_jpeg2000 = gf_isom_is_JPEG2000(isom_file);

    // Invoke gf_isom_set_sample_rap_group
    if (Size >= 2 * sizeof(u32) + sizeof(Bool)) {
        u32 sampleNumber = *((u32 *)Data);
        Data += sizeof(u32);
        u32 num_leading_samples = *((u32 *)Data);
        Data += sizeof(u32);
        Bool is_rap = (Data[0] % 2);
        gf_isom_set_sample_rap_group(isom_file, trackNumber, sampleNumber, is_rap, num_leading_samples);
    }

    // Clean up
    gf_isom_close(isom_file);

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

        LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    