#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Initialize the parameters for gf_isom_set_track_flags
    GF_ISOFile *movie = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (!movie) {
        return 0;
    }

    // Ensure size is large enough to extract required parameters
    if (size < sizeof(uint32_t) * 2 + sizeof(GF_ISOMTrackFlagOp)) {
        gf_isom_close(movie);
        return 0;
    }

    // Extract the parameters from the data
    uint32_t trackNumber = *((uint32_t *)data);
    uint32_t flags = *((uint32_t *)(data + sizeof(uint32_t)));
    GF_ISOMTrackFlagOp op = *((GF_ISOMTrackFlagOp *)(data + 2 * sizeof(uint32_t)));

    // Call the function-under-test
    gf_isom_set_track_flags(movie, trackNumber, flags, op);

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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
