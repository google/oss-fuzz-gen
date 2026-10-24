#include <stdint.h>
#include <stddef.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    if (size < sizeof(GF_ISOTrackID) + 2 * sizeof(u32)) {
        return 0;
    }

    // Initialize parameters for gf_isom_new_track
    GF_ISOFile *movie = gf_isom_open("temp.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (movie == NULL) {
        return 0;
    }

    // Extract parameters from the input data
    GF_ISOTrackID trakID = *((GF_ISOTrackID *)data);
    u32 MediaType = *((u32 *)(data + sizeof(GF_ISOTrackID)));
    u32 TimeScale = *((u32 *)(data + sizeof(GF_ISOTrackID) + sizeof(u32)));

    // Call the function under test
    gf_isom_new_track(movie, trakID, MediaType, TimeScale);

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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
