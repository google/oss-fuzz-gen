#include <cstdint>
#include <cstdio>
#include <cstdlib>

extern "C" {
    #include <tiffio.h>
}

extern "C" int LLVMFuzzerTestOneInput_221(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for creating non-NULL strings
    if (size < 3) {
        return 0;
    }

    // Initialize parameters for TIFFErrorExt
    thandle_t handle = (thandle_t)1; // Non-NULL handle, using 1 as an example
    const char *module = "testModule";
    const char *fmt = "testFormat";

    // Allocate memory for the void pointer and ensure it's non-NULL
    void *clientData = malloc(1);
    if (clientData == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Call the function-under-test
    TIFFErrorExt(handle, module, fmt, clientData);

    // Free the allocated memory
    free(clientData);

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

    LLVMFuzzerTestOneInput_221(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
