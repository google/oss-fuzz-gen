#include <stdint.h>
#include <stddef.h>
#include <gpac/isomedia.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    if (size < 10) {
        return 0; // Ensure there's enough data to extract meaningful values
    }

    // Initialize parameters for gf_isom_new_external_track
    GF_ISOFile *movie = gf_isom_open("temp.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (!movie) {
        return 0;
    }

    // Extract values from the input data
    GF_ISOTrackID trakID = (GF_ISOTrackID)data[0];
    GF_ISOTrackID refTrakID = (GF_ISOTrackID)data[1];
    u32 MediaType = (u32)data[2];
    u32 TimeScale = (u32)data[3];

    // Create a URI string from the remaining data
    size_t uri_length = size - 4;
    char *uri = (char *)malloc(uri_length + 1);
    if (!uri) {
        gf_isom_close(movie);
        return 0;
    }
    memcpy(uri, data + 4, uri_length);
    uri[uri_length] = '\0'; // Null-terminate the string

    // Call the function-under-test
    gf_isom_new_external_track(movie, trakID, refTrakID, MediaType, TimeScale, uri);

    // Clean up
    free(uri);
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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
