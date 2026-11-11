#include <cstdint>
#include <cstddef>
#include <cstring>  // Include this for std::memcpy

extern "C" {
    #include <tiffio.h>  // Wrap C library includes with extern "C"
}

extern "C" int LLVMFuzzerTestOneInput_230(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to form at least one float
    if (size < sizeof(float)) {
        return 0;
    }

    // Process each float in the input data
    for (size_t offset = 0; offset + sizeof(float) <= size; offset += sizeof(float)) {
        float value;
        // Copy the bytes from data into the float variable
        std::memcpy(&value, data + offset, sizeof(float));

        // Call the function-under-test
        TIFFSwabFloat(&value);
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

    LLVMFuzzerTestOneInput_230(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
