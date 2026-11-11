#include <cstdint>
#include <cstddef>
#include <cstring>

extern "C" {
    // Declaration of the function-under-test
    int plist_is_binary(const char *data, uint32_t size);
}

extern "C" int LLVMFuzzerTestOneInput_172(const uint8_t *data, size_t size) {
    // Ensure the data is not NULL and size is non-zero
    if (data == nullptr || size == 0) {
        return 0;
    }

    // Allocate memory for the input string and ensure it is null-terminated
    char *input = new char[size + 1];
    std::memcpy(input, data, size);
    input[size] = '\0';

    // Call the function-under-test
    plist_is_binary(input, static_cast<uint32_t>(size));

    // Clean up
    delete[] input;

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

    LLVMFuzzerTestOneInput_172(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
