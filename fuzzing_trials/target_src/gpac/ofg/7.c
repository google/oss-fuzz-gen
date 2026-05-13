#include <stdint.h>
#include <stdlib.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    // Initialize variables for function parameters
    GF_ISOFile *movie = gf_isom_open("temp.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (movie == NULL) {
        return 0;
    }

    // Ensure trakID, MediaType, and TimeScale are non-zero and within valid ranges
    GF_ISOTrackID trakID = (GF_ISOTrackID)(size > 0 ? data[0] : 1); // Use first byte or default to 1
    u32 MediaType = (u32)(size > 1 ? data[1] : GF_ISOM_MEDIA_VISUAL); // Use second byte or default to visual type
    u32 TimeScale = (u32)(size > 2 ? data[2] : 90000); // Use third byte or default to 90000

    // Call the function-under-test
    gf_isom_new_track(movie, trakID, MediaType, TimeScale);

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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
