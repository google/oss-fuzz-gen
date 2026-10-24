#include <stdint.h>
#include <stddef.h>
#include <gpac/isomedia.h>
#include <stdlib.h>  // Include for malloc and free

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    GF_ISOFile *movie = NULL;

    // Check if the input size is reasonable for processing
    if (size < 8) {
        return 0;  // Return early if the input size is too small
    }

    // Allocate a buffer to ensure data is null-terminated
    uint8_t *buffer = (uint8_t *)malloc(size + 1);
    if (!buffer) {
        return 0;  // Return if memory allocation fails
    }
    memcpy(buffer, data, size);
    buffer[size] = '\0';  // Null-terminate the buffer

    // Hypothetical function to initialize GF_ISOFile from a buffer.
    // Replace 'gf_isom_open' with the actual function if it exists.
    movie = gf_isom_open(buffer, size, GF_ISOM_OPEN_READ);

    if (movie) {
        // Call the function under test
        gf_isom_close(movie);
    }

    free(buffer);  // Free the allocated buffer

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
