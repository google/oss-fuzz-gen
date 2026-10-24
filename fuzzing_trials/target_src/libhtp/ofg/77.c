#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern int64_t bstr_util_mem_to_pint(const void *, size_t, int, size_t *);

int LLVMFuzzerTestOneInput_77(const uint8_t *data, size_t size) {
    if (size < sizeof(int) + sizeof(size_t)) {
        return 0; // Not enough data to extract necessary parameters
    }

    // Extract an integer from the input data
    int int_param = *((int *)data);

    // Extract a size_t value from the input data
    size_t size_param = *((size_t *)(data + sizeof(int)));

    // Call the function-under-test
    int64_t result = bstr_util_mem_to_pint(data, size, int_param, &size_param);

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

    LLVMFuzzerTestOneInput_77(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
