#include <sys/stat.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

// Assume the function is declared in a header file or elsewhere
int dwarf_get_LLE_name(unsigned int, const char **);

int LLVMFuzzerTestOneInput_145(const uint8_t *data, size_t size) {
    unsigned int index;
    const char *name = NULL;

    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Copy the first 4 bytes of data to index
    index = *(unsigned int *)data;

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_145(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
