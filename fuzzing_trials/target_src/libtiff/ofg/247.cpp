#include <cstdint>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_247(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to extract a uint16_t value
    if (size < sizeof(uint16_t)) {
        return 0;
    }

    // Extract a uint16_t value from the input data
    uint16_t codec = *(reinterpret_cast<const uint16_t*>(data));

    // Call the function-under-test
    int result = TIFFIsCODECConfigured(codec);

    // Use the result in some way to avoid compiler optimizations removing the call
    if (result) {
        // Do something if the codec is configured
    } else {
        // Do something if the codec is not configured
    }

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

    LLVMFuzzerTestOneInput_247(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
