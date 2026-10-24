#include <stdint.h>
#include <stdio.h>
#include <unistd.h>  // Include this for the definition of off64_t
#include <zlib.h>

extern uLong crc32_combine_gen64(off_t len2);

int LLVMFuzzerTestOneInput_79(const uint8_t *data, size_t size) {
    // Ensure there is enough data to construct an off_t value
    if (size < sizeof(off_t)) {
        return 0;
    }

    // Construct an off_t value from the input data
    off_t len2 = 0;
    for (size_t i = 0; i < sizeof(off_t); ++i) {
        len2 = (len2 << 8) | data[i];
    }

    // Call the function-under-test
    uLong result = crc32_combine_gen64(len2);

    // Print the result for debugging purposes (optional)
    printf("crc32_combine_gen64(%lld) = %lu\n", (long long)len2, result);

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

    LLVMFuzzerTestOneInput_79(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
