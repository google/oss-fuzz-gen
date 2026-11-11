#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include string.h for strdup
#include "gpac/isomedia.h"

int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;

    // Ensure the input data is null-terminated to avoid buffer overflow in gf_isom_open
    char *null_terminated_data = (char *)malloc(size + 1);
    if (!null_terminated_data) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Open the movie file using the null-terminated data
    movie = gf_isom_open(null_terminated_data, GF_ISOM_OPEN_READ, NULL);

    if (movie != NULL) {
        // Call the function-under-test
        gf_isom_close(movie);
    }

    // Free the allocated memory
    free(null_terminated_data);

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
