#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_68(const uint8_t *data, size_t size) {
    GF_ISOFile *movie;
    u32 trackNumber;

    // Initialize the GF_ISOFile structure
    movie = gf_isom_open((const char *)data, GF_ISOM_OPEN_READ, NULL);
    if (!movie) {
        return 0;
    }

    // Ensure trackNumber is within a reasonable range
    if (size >= sizeof(u32)) {
        trackNumber = *((u32 *)data) % 100; // Limiting track number to a reasonable range
    } else {
        trackNumber = 0; // Default track number if not enough data
    }

    // Call the function-under-test
    gf_isom_remove_track_from_root_od(movie, trackNumber);

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

    LLVMFuzzerTestOneInput_68(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
