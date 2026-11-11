#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Assuming the function is declared in an external library
int dwarf_get_RLE_name(unsigned int code, const char **name);

int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    unsigned int code;
    const char *name = NULL;

    // Ensure there's enough data to read an unsigned int
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Extract an unsigned int from the input data
    code = *(const unsigned int *)data;

    // Call the function-under-test
    int result = dwarf_get_RLE_name(code, &name);

    // Optionally print the result and name for debugging purposes
    if (name != NULL) {
        printf("Result: %d, Name: %s\n", result, name);
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

    LLVMFuzzerTestOneInput_26(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
