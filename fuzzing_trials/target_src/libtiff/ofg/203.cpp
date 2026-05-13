#include <cstdint>
#include <cstddef>
#include <tiffio.h>

extern "C" int LLVMFuzzerTestOneInput_203(const uint8_t *data, size_t size) {
    if (size < sizeof(uint16_t)) {
        return 0; // Early exit if there's not enough data to form a uint16_t
    }

    // Initialize a uint16_t variable from the input data
    uint16_t value;
    value = *(reinterpret_cast<const uint16_t*>(data));

    // Call the function-under-test
    TIFFSwabShort(&value);

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

    LLVMFuzzerTestOneInput_203(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
