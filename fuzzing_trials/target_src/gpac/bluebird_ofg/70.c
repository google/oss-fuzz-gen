#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "/src/gpac/include/gpac/isomedia.h"

int LLVMFuzzerTestOneInput_70(const uint8_t *data, size_t size) {
    // Initialize variables
    GF_ISOFile *movie = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_WRITE, NULL); // Open a dummy ISO file
    if (!movie) return 0;

    u32 trackNumber = 1; // Assuming track number 1 for testing
    u32 StreamDescriptionIndex = 1; // Assuming stream description index 1
    u32 colour_type = 1; // Arbitrary non-zero value
    u16 colour_primaries = 1; // Arbitrary non-zero value
    u16 transfer_characteristics = 1; // Arbitrary non-zero value
    u16 matrix_coefficients = 1; // Arbitrary non-zero value
    int full_range_flag = 1; // Use int instead of Bool for C compatibility
    u8 *icc_data = (u8 *)data; // Use fuzzer input data as ICC data
    u32 icc_size = (u32)size; // Use fuzzer input size as ICC size

    // Call the function-under-test
    gf_isom_set_visual_color_info(movie, trackNumber, StreamDescriptionIndex, colour_type, colour_primaries, transfer_characteristics, matrix_coefficients, full_range_flag, icc_data, icc_size);

    // Clean up
    gf_isom_close(movie);

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

    LLVMFuzzerTestOneInput_70(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
