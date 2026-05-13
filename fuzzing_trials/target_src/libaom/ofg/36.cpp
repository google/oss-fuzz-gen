#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>

extern "C" {
    // Assuming the function is defined in a C library
    int aom_uleb_encode_fixed_size(uint64_t value, size_t available, size_t fixed_size, uint8_t *buffer, size_t *encoded_size);
}

extern "C" int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    uint64_t value = 0;
    size_t available = 0;
    size_t fixed_size = 0;
    uint8_t buffer[256] = {0};  // Fixed buffer size
    size_t encoded_size = 0;

    if (size >= sizeof(uint64_t) + 2 * sizeof(size_t)) {
        // Extracting values from the input data
        std::memcpy(&value, data, sizeof(uint64_t));
        std::memcpy(&available, data + sizeof(uint64_t), sizeof(size_t));
        std::memcpy(&fixed_size, data + sizeof(uint64_t) + sizeof(size_t), sizeof(size_t));

        // Ensure available and fixed_size are within buffer limits
        available = available % 256;
        fixed_size = fixed_size % 256;

        // Call the function-under-test
        aom_uleb_encode_fixed_size(value, available, fixed_size, buffer, &encoded_size);
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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
