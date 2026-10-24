#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_133(const uint8_t *data, size_t size) {
    // Ensure that the size of the data is non-zero to create a valid symbol
    if (size == 0) {
        return 0;
    }

    // Create a JanetSymbol from the input data
    // JanetSymbol is essentially a const char*
    const char *symbolData = (const char *)data;

    // Ensure the symbol is null-terminated
    char *symbol = (char *)malloc(size + 1);
    if (symbol == NULL) {
        return 0;
    }
    memcpy(symbol, symbolData, size);
    symbol[size] = '\0';

    // Call the function-under-test
    Janet result = janet_wrap_symbol(symbol);

    // Clean up
    free(symbol);

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

    LLVMFuzzerTestOneInput_133(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
