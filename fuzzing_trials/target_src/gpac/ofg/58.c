#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

// Define the LLVMFuzzerTestOneInput function
int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract necessary parameters
    if (size < sizeof(u32) + sizeof(u64)) {
        return 0;
    }

    // Initialize the GF_ISOFile structure
    GF_ISOFile *movie = gf_isom_open(NULL, GF_ISOM_OPEN_WRITE, NULL);
    if (!movie) {
        return 0;
    }

    // Extract trackNumber and dur from the input data
    u32 trackNumber = *(const u32 *)data;
    u64 dur = *(const u64 *)(data + sizeof(u32));

    // Call the function-under-test
    gf_isom_force_track_duration(movie, trackNumber, dur);

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

    LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
