#include <cstdint>
#include <cstddef>
#include <cstring>
#include <iostream>

extern "C" {
    int aom_uleb_decode(const uint8_t *buffer, size_t buffer_size, uint64_t *value, size_t *length);
}

extern "C" int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    // Ensure that the size is large enough to perform meaningful decoding
    if (size < 1) {
        return 0;
    }

    // Initialize the output parameters
    uint64_t decoded_value = 0;
    size_t decoded_length = 0;

    // Call the function-under-test
    aom_uleb_decode(data, size, &decoded_value, &decoded_length);

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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
