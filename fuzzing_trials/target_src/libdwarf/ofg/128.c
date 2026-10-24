#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <dwarf.h>

extern int dwarf_get_MACRO_name(unsigned int, const char **);

int LLVMFuzzerTestOneInput_128(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for our needs
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Extract an unsigned int from the input data
    unsigned int macro_code = *(unsigned int *)data;

    // Allocate memory for the name pointer
    const char *name = NULL;

    // Call the function-under-test
    int result = dwarf_get_MACRO_name(macro_code, &name);

    // If name was set, free it if necessary (depends on the function's documentation)
    // In this case, we assume it does not need to be freed as it's a const char*

    // Return 0 to indicate success
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

    LLVMFuzzerTestOneInput_128(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
