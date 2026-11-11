#include <stdint.h>
#include <stddef.h>

// Function-under-test
double bam_auxB2f(const uint8_t *data, uint32_t size);

int LLVMFuzzerTestOneInput_52(const uint8_t *data, size_t size) {
    // Ensure size is at least 1 to avoid passing a NULL pointer
    if (size < 1) {
        return 0;
    }

    // Cast size to uint32_t for the function call
    uint32_t dataSize = (uint32_t)size;

    // Call the function-under-test
    double result = bam_auxB2f(data, dataSize);

    // Use the result in some way to avoid compiler optimizations
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_52(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
