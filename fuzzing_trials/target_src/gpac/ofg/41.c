#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>
#include <gpac/setup.h> // Include this to ensure Bool is correctly defined by the library

// Define u32 if it is not defined by the included headers
typedef uint32_t u32;

int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    GF_ISOFile *movie;
    u32 trackNumber;
    u32 StreamDescriptionIndex;
    Bool remove;

    // Initialize the parameters
    movie = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (!movie) {
        return 0;
    }

    // Ensure size is sufficient for extracting parameters
    if (size < sizeof(u32) * 2 + sizeof(Bool)) {
        gf_isom_close(movie);
        return 0;
    }

    // Extract parameters from data
    trackNumber = *((u32*)data);
    StreamDescriptionIndex = *((u32*)(data + sizeof(u32)));
    remove = (Bool)(*((uint8_t*)(data + 2 * sizeof(u32))) % 2); // Ensure remove is a valid Bool value

    // Call the function-under-test
    gf_isom_set_image_sequence_alpha(movie, trackNumber, StreamDescriptionIndex, remove);

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

    LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
