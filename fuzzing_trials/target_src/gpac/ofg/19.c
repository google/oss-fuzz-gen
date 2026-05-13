#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Assuming the necessary headers for GF_ISOFile, GF_ISOTrackID, and GF_EXPORT are included
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_19(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    GF_ISOFile *movie = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (!movie) {
        return 0;
    }

    GF_ISOTrackID trakID = 1;
    GF_ISOTrackID refTrakID = 2;
    u32 MediaType = GF_ISOM_MEDIA_VISUAL;
    u32 TimeScale = 1000;
    
    // Ensure the URI is null-terminated and not NULL
    char uri[256];
    if (size > 0) {
        size_t uri_len = size < 255 ? size : 255;
        memcpy(uri, data, uri_len);
        uri[uri_len] = '\0';
    } else {
        strcpy(uri, "http://example.com");
    }

    // Call the function under test
    gf_isom_new_external_track(movie, trakID, refTrakID, MediaType, TimeScale, uri);

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

    LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
