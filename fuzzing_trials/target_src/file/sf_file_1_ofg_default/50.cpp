#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <magic.h>

extern "C" int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    // Initialize variables before goto
    struct magic_set *magic = NULL;
    int descriptor;
    const char *result;

    // Ensure size is sufficient for an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Initialize magic_set
    magic = magic_open(MAGIC_NONE);
    if (magic == NULL) {
        return 0;
    }

    // Load default magic database
    if (magic_load(magic, NULL) != 0) {
        magic_close(magic);
        return 0;
    }

    // Use the first 4 bytes of data as an integer descriptor
    descriptor = *(reinterpret_cast<const int*>(data));

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

    LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
