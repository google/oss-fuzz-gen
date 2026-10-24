#include <stdint.h>
#include <zlib.h>
#include <sys/types.h>
#include <unistd.h>  // Include this for off_t
#include <stdio.h>   // Include this for NULL definition

int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract uLong and off_t values
    if (size < sizeof(uLong) * 2 + sizeof(off_t)) {
        return 0;
    }

    // Extract uLong values from the input data
    uLong adler1 = *(const uLong *)data;
    uLong adler2 = *(const uLong *)(data + sizeof(uLong));

    // Extract off_t value from the input data
    off_t len2 = *(const off_t *)(data + sizeof(uLong) * 2);

    // Call the function-under-test
    uLong result = adler32_combine(adler1, adler2, len2);

    // Use the result to prevent compiler optimizations
    (void)result;

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

    LLVMFuzzerTestOneInput_53(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
