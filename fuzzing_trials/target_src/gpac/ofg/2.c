#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_2(const uint8_t *data, size_t size) {
    // Initialize the parameters for the function-under-test
    GF_ISOFile *movie = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (!movie) {
        return 0;
    }

    // Ensure that trackNumber and StreamDescriptionIndex are within a valid range
    u32 trackNumber = (size > 0) ? data[0] % 10 + 1 : 1; // Example range for trackNumber
    u32 StreamDescriptionIndex = (size > 1) ? data[1] % 5 + 1 : 1; // Example range for StreamDescriptionIndex
    u16 bitDepth = (size > 2) ? data[2] % 16 + 1 : 8; // Example bit depth

    // Call the function-under-test
    gf_isom_set_visual_bit_depth(movie, trackNumber, StreamDescriptionIndex, bitDepth);

    // Close the movie file
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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
