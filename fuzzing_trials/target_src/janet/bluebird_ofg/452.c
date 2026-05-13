#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_452(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    // Ensure the data is null-terminated to safely convert to a string
    char *symbol_str = (char *)malloc(size + 1);
    if (!symbol_str) {
        janet_deinit(); // Clean up Janet environment
        return 0;
    }
    memcpy(symbol_str, data, size);
    symbol_str[size] = '\0';

    // Convert the string to a JanetSymbol
    JanetSymbol symbol = janet_symbol((const uint8_t *)symbol_str, (int32_t)size);

    // Call the function-under-test
    Janet result = janet_wrap_symbol(symbol);

    // Clean up
    free(symbol_str);

    // Deinitialize the Janet environment
    janet_deinit();

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

    LLVMFuzzerTestOneInput_452(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
