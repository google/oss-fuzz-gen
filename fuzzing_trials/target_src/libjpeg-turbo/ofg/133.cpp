#include <cstddef>
#include <cstdint>

extern "C" {
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.0.x/turbojpeg.h"
    #include "/src/libjpeg-turbo.3.1.x/src/turbojpeg.h"
}

extern "C" int LLVMFuzzerTestOneInput_133(const uint8_t *data, size_t size) {
    // Ensure that size is not zero to avoid passing zero to tjAlloc
    if (size == 0) {
        return 0;
    }

    // Use the size of the input data to allocate memory
    int allocSize = static_cast<int>(size);

    // Call the function-under-test
    unsigned char *allocatedMemory = tjAlloc(allocSize);

    // Check if the allocation was successful
    if (allocatedMemory != NULL) {
        // Simulate some usage of the allocated memory
        for (int i = 0; i < allocSize; ++i) {
            allocatedMemory[i] = data[i % size];
        }

        // Free the allocated memory
        tjFree(allocatedMemory);
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

    LLVMFuzzerTestOneInput_133(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
