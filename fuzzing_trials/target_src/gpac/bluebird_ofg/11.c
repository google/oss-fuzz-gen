#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/gpac/include/gpac/isomedia.h"

int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for creating a null-terminated string
    if (size < 1) {
        return 0;
    }

    // Allocate memory for the URL string and ensure it is null-terminated
    char *url_string = (char *)malloc(size + 1);
    if (url_string == NULL) {
        return 0;
    }
    memcpy(url_string, data, size);
    url_string[size] = '\0';

    // Create a dummy GF_ISOFile object
    GF_ISOFile *movie = gf_isom_open("dummy.mp4", GF_ISOM_OPEN_WRITE, NULL);
    if (movie == NULL) {
        free(url_string);
        return 0;
    }

    // Call the function under test
    gf_isom_set_root_od_url(movie, url_string);

    // Clean up
    gf_isom_close(movie);
    free(url_string);

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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
