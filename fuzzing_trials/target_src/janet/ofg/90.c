#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Function-under-test
void *janet_calloc(size_t num, size_t size);

int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Not enough data to extract two size_t values
    }

    // Extract two size_t values from the input data
    size_t num = (size_t)data[0];
    size_t elem_size = (size_t)data[1];

    // Call the function-under-test
    void *result = janet_calloc(num, elem_size);

    // Free the allocated memory if not NULL
    if (result != NULL) {
        free(result);
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

    LLVMFuzzerTestOneInput_90(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
