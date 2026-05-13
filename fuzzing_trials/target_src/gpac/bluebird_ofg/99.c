#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "/src/gpac/include/gpac/isomedia.h"

int LLVMFuzzerTestOneInput_99(const uint8_t *data, size_t size) {
    // Initialize variables
    GF_ISOFile *movie;
    u32 trackNumber;
    u32 flags;
    GF_ISOMTrackFlagOp op;
    
    // Ensure the input size is sufficient for our needs
    if (size < sizeof(u32) * 3) {
        return 0;
    }

    // Create a new ISO file for testing
    movie = gf_isom_open("test.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (!movie) {
        return 0;
    }

    // Extract values from the data
    trackNumber = *((u32*)data);
    flags = *((u32*)(data + sizeof(u32)));
    op = (GF_ISOMTrackFlagOp)(*((u32*)(data + sizeof(u32) * 2)) % 3); // Assume 3 possible operations

    // Call the function-under-test
    gf_isom_set_track_flags(movie, trackNumber, flags, op);

    // Close the ISO file
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

    LLVMFuzzerTestOneInput_99(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
