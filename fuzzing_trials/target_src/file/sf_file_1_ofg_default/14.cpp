#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <magic.h>

extern "C" {
    // Function-under-test
    const char * magic_descriptor(struct magic_set *, int);
}

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0; // Ensure there's enough data for an int
    }

    // Initialize a magic_set structure
    struct magic_set *magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0; // If initialization fails, exit
    }

    // Load default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0; // If loading fails, exit
    }

    // Extract an integer from the data
    int descriptor = *(reinterpret_cast<const int*>(data));

    // Call the function-under-test
    const char *result = magic_descriptor(magic, descriptor);

    // Print the result for debugging purposes (optional)
    if (result != NULL) {
        printf("Magic descriptor result: %s\n", result);
    }

    // Cleanup
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

    LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
