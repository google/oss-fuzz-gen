#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    GF_ISOFile *movie;
    u32 trackNumber;
    u64 ctime;
    u64 mtime;

    // Ensure the data size is sufficient to extract required parameters
    if (size < sizeof(u32) + 2 * sizeof(u64)) {
        return 0;
    }

    // Initialize the movie structure
    movie = gf_isom_open("temp.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (movie == NULL) {
        return 0;
    }

    // Extract parameters from the input data
    trackNumber = *((u32 *)data);
    ctime = *((u64 *)(data + sizeof(u32)));
    mtime = *((u64 *)(data + sizeof(u32) + sizeof(u64)));

    // Call the function-under-test
    gf_isom_set_track_creation_time(movie, trackNumber, ctime, mtime);

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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
