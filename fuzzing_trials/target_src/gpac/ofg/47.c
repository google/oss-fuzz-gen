#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <gpac/isomedia.h>
#include <gpac/constants.h> // Include for u32 type

int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    // Assuming fixed offsets for demonstration purposes
    const size_t GF_ISOFile_offset = 128; // Hypothetical offset size
    const size_t GF_DOVIDecoderConfigurationRecord_offset = 64; // Hypothetical offset size

    // Ensure the size is sufficient to extract parameters
    if (size < GF_ISOFile_offset + sizeof(u32) * 2 + GF_DOVIDecoderConfigurationRecord_offset) {
        return 0;
    }

    // Allocate memory to copy input data to ensure it's not modified
    uint8_t *data_copy = (uint8_t *)malloc(size);
    if (!data_copy) {
        return 0; // Handle memory allocation failure
    }
    memcpy(data_copy, data, size);

    // Initialize parameters
    GF_ISOFile *movie = (GF_ISOFile *)(data_copy);
    u32 trackNumber = 1;  // Example track number
    u32 StreamDescriptionIndex = 1;  // Example stream description index

    // Calculate offset for dvcc
    size_t offset = GF_ISOFile_offset + sizeof(u32) * 2;
    GF_DOVIDecoderConfigurationRecord *dvcc = (GF_DOVIDecoderConfigurationRecord *)(data_copy + offset);

    // Call the function-under-test
    gf_isom_set_dolby_vision_profile(movie, trackNumber, StreamDescriptionIndex, dvcc);

    // Free the allocated memory
    free(data_copy);

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

    LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
