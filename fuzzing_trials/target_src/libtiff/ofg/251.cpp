#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <tiffio.h>

extern "C" {
    // Function signature from the TIFF library
    void _TIFFmemcpy(void *dest, const void *src, tmsize_t size);
}

extern "C" int LLVMFuzzerTestOneInput_251(const uint8_t *data, size_t size) {
    // Ensure there is enough data to perform a meaningful test
    if (size < 2) {
        return 0;
    }

    // Split the input data into two equal parts for source and destination
    size_t half_size = size / 2;

    // Allocate memory for destination and source buffers
    void *dest = malloc(half_size);
    const void *src = static_cast<const void *>(data);

    if (dest == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Ensure the destination buffer is filled with non-zero data
    memset(dest, 0xFF, half_size);

    // Call the function-under-test
    _TIFFmemcpy(dest, src, static_cast<tmsize_t>(half_size));

    // Free allocated memory
    free(dest);

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

    LLVMFuzzerTestOneInput_251(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
