#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>

// Function-under-test
void *hoedown_calloc(size_t count, size_t size);

int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    // Ensure size is at least large enough to extract two size_t values
    if (size < 2 * sizeof(size_t)) {
        return 0;
    }

    // Extract two size_t values from the input data
    size_t count = *((size_t *)data);
    size_t elem_size = *((size_t *)(data + sizeof(size_t)));

    // Limit count and elem_size to prevent excessive memory allocation
    if (count > SIZE_MAX / elem_size || elem_size > SIZE_MAX / count) {
        return 0;
    }

    // Call the function-under-test
    void *result = hoedown_calloc(count, elem_size);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
