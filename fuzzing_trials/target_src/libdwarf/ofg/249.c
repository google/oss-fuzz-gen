#include <stdint.h>
#include <stddef.h>
#include <dwarf.h>

extern int dwarf_get_OP_name(unsigned int op, const char **op_name);

int LLVMFuzzerTestOneInput_249(const uint8_t *data, size_t size) {
    unsigned int op;
    const char *op_name = NULL;

    // Ensure there's enough data to read an unsigned int
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Copy bytes from data to op
    op = *(const unsigned int *)data;

    // Call the function-under-test
    dwarf_get_OP_name(op, &op_name);

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

    LLVMFuzzerTestOneInput_249(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
