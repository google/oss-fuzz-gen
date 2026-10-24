#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Assume the function is defined in an external library
extern int dwarf_get_ISA_name(unsigned int isa, const char **name);

int LLVMFuzzerTestOneInput_92(const uint8_t *data, size_t size) {
    unsigned int isa;
    const char *name = NULL;

    // Ensure there is enough data to read an unsigned int
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Interpret the first bytes of data as an unsigned int
    isa = *(unsigned int *)data;

    // Call the function-under-test
    int result = dwarf_get_ISA_name(isa, &name);

    // Optionally, print the result for debugging purposes
    if (result == 0 && name != NULL) {
        printf("ISA: %u, Name: %s\n", isa, name);
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

    LLVMFuzzerTestOneInput_92(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
