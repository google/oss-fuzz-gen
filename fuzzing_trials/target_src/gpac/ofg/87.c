#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = gf_isom_open(NULL, GF_ISOM_OPEN_WRITE, NULL);
    if (!movie) return 0;

    u32 trackNumber = 1; // Assuming a valid track number
    GF_ESD esd;
    memset(&esd, 0, sizeof(GF_ESD)); // Initialize the GF_ESD structure

    // Allocate memory for URLname and URNname, and ensure they are null-terminated
    char URLname[256];
    char URNname[256];
    snprintf(URLname, sizeof(URLname), "http://example.com");
    snprintf(URNname, sizeof(URNname), "urn:example");

    u32 outDescriptionIndex;

    // Call the function-under-test
    gf_isom_new_mpeg4_description(movie, trackNumber, &esd, URLname, URNname, &outDescriptionIndex);

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

    LLVMFuzzerTestOneInput_87(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
