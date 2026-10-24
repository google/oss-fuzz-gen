#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function-under-test declaration
char * bstr_util_memdup_to_c(const void *src, size_t size);

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Ensure that the input data is not NULL and has a non-zero size
    if (data == NULL || size == 0) {
        return 0;
    }

    // Call the function-under-test
    char *result = bstr_util_memdup_to_c((const void *)data, size);

    // If the function returns a non-NULL pointer, free the allocated memory
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
