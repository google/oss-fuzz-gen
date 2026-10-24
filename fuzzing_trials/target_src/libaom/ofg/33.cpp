#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

extern "C" {
    int aom_uleb_decode(const uint8_t *, size_t, uint64_t *, size_t *);
}

extern "C" int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough to test the function
    if (size < 1) {
        return 0;
    }

    // Allocate and initialize the output variables
    uint64_t decoded_value = 0;
    size_t decoded_size = 0;

    // Call the function-under-test
    int result = aom_uleb_decode(data, size, &decoded_value, &decoded_size);

    // Use the result, decoded_value, and decoded_size in some way to prevent
    // unused variable warnings (e.g., simple logging or assertions)
    (void)result;
    (void)decoded_value;
    (void)decoded_size;

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
