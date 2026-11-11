#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring> // Include for memcpy

extern "C" {
    void plist_mem_free(void *);
}

extern "C" int LLVMFuzzerTestOneInput_103(const uint8_t *data, size_t size) {
    // Check if input size is zero and return early if true
    if (size == 0) {
        return 0;
    }

    // Allocate some memory to be freed
    void *memory = malloc(size + 1); // Ensure non-zero size allocation

    // Check if memory allocation was successful
    if (memory == nullptr) {
        return 0; // Exit if allocation failed
    }

    // Use memcpy instead of a loop for copying data
    memcpy(memory, data, size);

    // Null-terminate the data to avoid any potential overflow issues
    static_cast<uint8_t *>(memory)[size] = '\0';

    // Call the function-under-test
    plist_mem_free(memory);

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

    LLVMFuzzerTestOneInput_103(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
