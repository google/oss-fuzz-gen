#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring> // Include the necessary header for memcpy

extern "C" {
    void plist_mem_free(void *);
}

extern "C" int LLVMFuzzerTestOneInput_102(const uint8_t *data, size_t size) {
    // Allocate memory and copy the input data to it
    void *memory = malloc(size);
    if (memory == nullptr) {
        return 0; // If memory allocation fails, exit early
    }

    // Copy the input data to the allocated memory
    memcpy(memory, data, size);

    // Call the function-under-test
    plist_mem_free(memory);

    // Memory is freed within plist_mem_free, so no need to free it here

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

    LLVMFuzzerTestOneInput_102(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
