#include <cstdint>
#include <cstddef>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_81(const uint8_t *data, size_t size) {
    // Ensure the size is a multiple of 3 for the function to work properly
    if (size < 3 || size % 3 != 0) {
        return 0;
    }

    // Create a mutable copy of the input data
    uint8_t *mutableData = new uint8_t[size];
    for (size_t i = 0; i < size; ++i) {
        mutableData[i] = data[i];
    }

    // Call the function-under-test
    TIFFSwabArrayOfTriples(mutableData, static_cast<tmsize_t>(size / 3));

    // Clean up allocated memory
    delete[] mutableData;

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

    LLVMFuzzerTestOneInput_81(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
