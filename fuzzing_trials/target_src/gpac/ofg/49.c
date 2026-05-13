#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
    GF_ISOFile *movie;
    char *url_string;

    // Ensure that the size is sufficient for a null-terminated string
    if (size < 1) {
        return 0;
    }

    // Initialize a GF_ISOFile object
    movie = gf_isom_open(NULL, GF_ISOM_OPEN_WRITE, NULL);
    if (movie == NULL) {
        return 0;
    }

    // Allocate memory for the URL string and ensure it is null-terminated
    url_string = (char *)malloc(size + 1);
    if (url_string == NULL) {
        gf_isom_close(movie);
        return 0;
    }
    memcpy(url_string, data, size);
    url_string[size] = '\0';

    // Call the function-under-test
    gf_isom_set_root_od_url(movie, url_string);

    // Clean up
    free(url_string);
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

    LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
