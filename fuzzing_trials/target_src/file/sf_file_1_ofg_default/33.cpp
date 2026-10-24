#include <cstddef>
#include <cstdint>
#include <stdlib.h>
#include <cstring> // Include the C++ header for strlen

extern "C" {
    #include <magic.h> // Include the magic header within extern "C"
}

extern "C" int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Initialize magic_set structure
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0;
    }

    // Load a default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0;
    }

    // Extract an integer from the data
    int descriptor = *(reinterpret_cast<const int*>(data));

    // Call the function-under-test
    const char *result = magic_descriptor(magic, descriptor);

    // Use the result in some way to avoid compiler optimizations
    if (result != NULL) {
        // Just a dummy operation to use the result
        volatile size_t len = strlen(result);
        (void)len;
    }

    // Clean up
    magic_close(magic);

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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
