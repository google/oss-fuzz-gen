#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

// Function-under-test
void * hoedown_calloc(size_t num, size_t size);

int LLVMFuzzerTestOneInput_11(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract two size_t values
    if (size < sizeof(size_t) * 2) {
        return 0;
    }

    // Extract two size_t values from the input data
    size_t num = *(const size_t *)data;
    size_t elem_size = *(const size_t *)(data + sizeof(size_t));

    // Check for potential overflow in multiplication
    if (num != 0 && elem_size > SIZE_MAX / num) {
        return 0;
    }

    // Call the function-under-test
    void *result = hoedown_calloc(num, elem_size);

    // If the allocation was successful, free the allocated memory
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
