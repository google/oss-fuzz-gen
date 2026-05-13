#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

// Assume the function is declared in an external library
extern int dwarf_set_stringcheck(int);

int LLVMFuzzerTestOneInput_111(const uint8_t *data, size_t size) {
    // Ensure that we have at least 1 byte to read an integer value
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int stringcheck_value = *(const int *)data;

    // Call the function-under-test with the extracted integer value
    dwarf_set_stringcheck(stringcheck_value);

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

    LLVMFuzzerTestOneInput_111(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
