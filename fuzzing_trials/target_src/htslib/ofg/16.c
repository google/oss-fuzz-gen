#include <stdint.h>
#include <stddef.h>

// Function-under-test declaration
double bam_aux2f(const uint8_t *aux);

int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Ensure the data is not empty
    if (size == 0) {
        return 0;
    }

    // Call the function-under-test with the provided data
    double result = bam_aux2f(data);

    // Optionally, you can add some checks or logging based on the result
    // For example, you could print the result or check if it falls within expected ranges

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

    LLVMFuzzerTestOneInput_16(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
