#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Ensure the function is declared properly
extern uint64_t janet_optuinteger64(const Janet *argv, int32_t n, int32_t def, uint64_t fallback);

int LLVMFuzzerTestOneInput_188(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient
    if (size < sizeof(Janet) + sizeof(int32_t) * 2 + sizeof(uint64_t)) {
        return 0;
    }

    // Initialize the parameters for janet_optuinteger64
    const Janet *argv = (const Janet *)data;
    int32_t n = *(const int32_t *)(data + sizeof(Janet));
    int32_t def = *(const int32_t *)(data + sizeof(Janet) + sizeof(int32_t));
    uint64_t fallback = *(const uint64_t *)(data + sizeof(Janet) + sizeof(int32_t) * 2);

    // Validate the input data to avoid invalid memory access
    if (n < 0 || n >= size / sizeof(Janet)) {
        return 0;
    }

    // Call the function-under-test
    uint64_t result = janet_optuinteger64(argv, n, def, fallback);

    // Use result in some way to avoid compiler optimizations removing the call
    if (result == 0) {
        return 0;
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

    LLVMFuzzerTestOneInput_188(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
