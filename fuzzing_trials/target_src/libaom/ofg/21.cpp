#include <cstdint>
#include <cstddef>

// Assuming the function is defined in an external C library
extern "C" {
    size_t aom_uleb_size_in_bytes(uint64_t value);
}

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to interpret as a uint64_t
    if (size < sizeof(uint64_t)) {
        return 0;
    }

    // Interpret the first 8 bytes of data as a uint64_t
    uint64_t value = 0;
    for (size_t i = 0; i < sizeof(uint64_t); ++i) {
        value |= static_cast<uint64_t>(data[i]) << (i * 8);
    }

    // Call the function-under-test
    size_t result = aom_uleb_size_in_bytes(value);

    // Use the result in some way to prevent compiler optimizations from removing the call
    volatile size_t prevent_optimization = result;
    (void)prevent_optimization;

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

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
