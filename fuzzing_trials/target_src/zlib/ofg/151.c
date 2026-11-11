#include <stdint.h>
#include <stddef.h>
#include <zlib.h>
#include <stdio.h>
#include <inttypes.h> // Include this for PRId64
#include <sys/types.h> // Include this for off_t

int LLVMFuzzerTestOneInput_151(const uint8_t *data, size_t size) {
    if (size < sizeof(uLong) * 2 + sizeof(off_t)) {
        return 0;
    }

    uLong adler1 = *(const uLong *)(data);
    uLong adler2 = *(const uLong *)(data + sizeof(uLong));
    off_t len2 = *(const off_t *)(data + 2 * sizeof(uLong));

    // Call the function-under-test
    uLong result = adler32_combine(adler1, adler2, len2);

    // Print the result to ensure the function is called
    printf("Result: %lu\n", result);

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

    LLVMFuzzerTestOneInput_151(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
