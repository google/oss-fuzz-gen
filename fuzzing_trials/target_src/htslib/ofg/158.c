#include <stdint.h>
#include <stddef.h>

// Function-under-test
uint32_t bam_auxB_len(const uint8_t *data);

int LLVMFuzzerTestOneInput_158(const uint8_t *data, size_t size) {
    // Ensure that data is not NULL and size is greater than 0
    if (data == NULL || size == 0) {
        return 0;
    }

    // Call the function-under-test
    uint32_t result = bam_auxB_len(data);

    // Use the result in some way to prevent compiler optimizations from removing the call
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

    LLVMFuzzerTestOneInput_158(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
