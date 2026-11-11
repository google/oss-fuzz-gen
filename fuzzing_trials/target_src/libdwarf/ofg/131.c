#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Assume the function is declared in an external library
extern int dwarf_get_IDX_name(unsigned int idx, const char **name);

int LLVMFuzzerTestOneInput_131(const uint8_t *data, size_t size) {
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    unsigned int idx;
    const char *name = NULL;

    // Copy the first few bytes of data into idx
    idx = *(unsigned int *)data;

    // Call the function-under-test
    int result = dwarf_get_IDX_name(idx, &name);

    // Optionally, you can print the result and name for debugging purposes
    if (name != NULL) {
        printf("Result: %d, Name: %s\n", result, name);
    } else {
        printf("Result: %d, Name: NULL\n", result);
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

    LLVMFuzzerTestOneInput_131(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
