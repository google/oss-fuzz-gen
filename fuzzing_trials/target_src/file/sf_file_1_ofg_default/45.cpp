#include <stdint.h>
#include <stdlib.h>
#include <magic.h>

extern "C" int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    struct magic_set *magic = NULL;
    int descriptor = 0;
    const char *result;

    // Initialize the magic_set structure
    magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0;
    }

    // Load the default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0;
    }

    // Ensure the descriptor is within a valid range
    if (size > 0) {
        descriptor = static_cast<int>(data[0]);  // Use the first byte of data as descriptor
    }

    // Call the function-under-test
    result = magic_descriptor(magic, descriptor);

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

    LLVMFuzzerTestOneInput_45(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
