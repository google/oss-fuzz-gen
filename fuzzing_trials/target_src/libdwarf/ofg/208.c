#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <libdwarf.h>

extern int dwarf_get_SECT_name(unsigned int, const char **);

int LLVMFuzzerTestOneInput_208(const uint8_t *data, size_t size) {
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    unsigned int index = *(unsigned int *)data;
    const char *name = NULL;

    // Call the function-under-test
    int result = dwarf_get_SECT_name(index, &name);

    // Optionally, you can perform some checks or operations on `name` and `result`
    // For example:
    if (result == DW_DLV_OK && name != NULL) {
        // Do something with the name
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

    LLVMFuzzerTestOneInput_208(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
