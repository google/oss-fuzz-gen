#include <stdint.h>
#include <stddef.h>

// Function-under-test
double bam_aux2f(const uint8_t *data);

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    // Ensure that the data is not NULL and has at least one byte
    if (data == NULL || size == 0) {
        return 0;
    }

    // Call the function-under-test
    double result = bam_aux2f(data);

    // Use the result in some way to prevent compiler optimizations
    // (this is a dummy operation, as we are primarily interested in testing the function)
    if (result == 0.0) {
        return 1;
    }

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

    LLVMFuzzerTestOneInput_17(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
