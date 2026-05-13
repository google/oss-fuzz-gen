#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

// Assume the function is defined in an external library
extern int dwarf_set_reloc_application(int);

int LLVMFuzzerTestOneInput_110(const uint8_t *data, size_t size) {
    // Initialize the parameter for the function-under-test
    int param = 0;

    // Ensure we have at least 4 bytes to read an integer
    if (size >= sizeof(int)) {
        // Cast the input data to an integer
        param = *((int *)data);
    }

    // Call the function-under-test
    dwarf_set_reloc_application(param);

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

    LLVMFuzzerTestOneInput_110(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
