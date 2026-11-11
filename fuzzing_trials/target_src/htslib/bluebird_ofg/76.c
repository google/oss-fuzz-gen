#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

extern double bam_auxB2f(const uint8_t *, uint32_t);

int LLVMFuzzerTestOneInput_76(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for a uint32_t
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Use the first four bytes of data as a uint32_t value
    uint32_t value = *(const uint32_t *)data;

    // Call the function-under-test
    double result = bam_auxB2f(data, value);

    // Use the result in some way to prevent compiler optimizations
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

    LLVMFuzzerTestOneInput_76(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
