#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Function prototype for the function-under-test
long libbpf_get_error(const void *ptr);

// Fuzzing harness for the function-under-test
int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    // Ensure the data is not NULL and size is greater than 0
    if (data == NULL || size == 0) {
        return 0;
    }

    // Call the function-under-test with the data
    long result = libbpf_get_error((const void *)data);

    // Optionally, print the result for debugging purposes
    printf("libbpf_get_error result: %ld\n", result);

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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
