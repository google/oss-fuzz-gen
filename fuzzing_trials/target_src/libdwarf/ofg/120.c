#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Assume the function is defined in some library we are linking against
int dwarf_get_LLE_name(unsigned int, const char **);

int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function call
    unsigned int index;
    const char *name = NULL;

    // Ensure there is enough data to read an unsigned int
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Initialize the index from the input data
    index = *((unsigned int *)data);

    // Call the function-under-test
    dwarf_get_LLE_name(index, &name);

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

    LLVMFuzzerTestOneInput_120(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
