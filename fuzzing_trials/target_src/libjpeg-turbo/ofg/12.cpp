#include <stddef.h>
#include <stdint.h>
#include <cstdlib> // Include the C++ header for free
#include <cstring> // Include C++ header for memcpy
#include <iostream> // Include C++ header for debugging output

extern "C" {
    // Include the header where tj3Alloc is declared
    void * tj3Alloc(size_t);
}

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    // Ensure size is not zero to avoid allocating zero bytes
    if (size == 0) {
        return 0;
    }

    // Call the function-under-test with the size derived from the input
    void *allocated_memory = tj3Alloc(size);

    // Check if allocation was successful
    if (allocated_memory == nullptr) {
        std::cerr << "Allocation failed for size: " << size << std::endl;
        return 0;
    }

    // Use the allocated memory to increase code coverage
    // Copy the input data into the allocated memory
    memcpy(allocated_memory, data, size);

    // Perform additional operations on the allocated memory
    // Example: Modify the memory content to simulate usage
    for (size_t i = 0; i < size; ++i) {
        static_cast<uint8_t*>(allocated_memory)[i] ^= 0xFF; // Invert bits
    }

    // Free the allocated memory
    free(allocated_memory);

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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
