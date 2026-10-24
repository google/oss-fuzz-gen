#include <cstdint>
#include <cstdlib>
#include <tiffio.h>

extern "C" {
    void* _TIFFrealloc(void* ptr, tmsize_t size);
    void* _TIFFmalloc(tmsize_t size);
    void _TIFFfree(void* ptr);
}

extern "C" int LLVMFuzzerTestOneInput_189(const uint8_t *data, size_t size) {
    // Initialize a non-NULL pointer for the initial allocation
    tmsize_t initial_size = 10; // Arbitrary non-zero size
    void* ptr = _TIFFmalloc(initial_size);
    if (ptr == NULL) {
        return 0; // If allocation fails, exit the fuzzer
    }

    // Use the input data to determine the new size for reallocation
    tmsize_t new_size = static_cast<tmsize_t>(size);

    // Call the function-under-test
    void* new_ptr = _TIFFrealloc(ptr, new_size);

    // Check if reallocation was successful
    if (new_ptr != NULL) {
        // If the reallocation was successful and the new size is zero, 
        // the pointer should be freed as per the C standard library semantics.
        if (new_size == 0) {
            _TIFFfree(new_ptr);
        }
    } else {
        // If reallocation failed and new size is not zero, free the original pointer
        if (new_size != 0) {
            _TIFFfree(ptr);
        }
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

    LLVMFuzzerTestOneInput_189(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
