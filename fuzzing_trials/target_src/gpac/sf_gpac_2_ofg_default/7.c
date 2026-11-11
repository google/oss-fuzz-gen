#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <gpac/isomedia.h>

int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;
    u64 top_box_start = 0;

    // Ensure the data is null-terminated for gf_isom_open
    char *data_copy = (char *)malloc(size + 1);
    if (data_copy == NULL) {
        return 0;
    }
    memcpy(data_copy, data, size);
    data_copy[size] = '\0';

    // Initialize movie with the data
    movie = gf_isom_open(data_copy, GF_ISOM_OPEN_READ, NULL);
    free(data_copy); // Free the allocated memory for data_copy
    if (movie == NULL) {
        return 0;
    }

    // Call the function-under-test
    gf_isom_reset_data_offset(movie, &top_box_start);

    // Cleanup
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
