#include <stdint.h>
#include <string.h>
#include "/src/janet/src/include/janet.h"

// Ensure that the Janet library is initialized before use
void initialize_janet_295() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

int LLVMFuzzerTestOneInput_295(const uint8_t *data, size_t size) {
    // Ensure the input data is not null and has a valid size
    if (data == NULL || size == 0) {
        return 0;
    }

    // Initialize Janet if it's not already initialized
    initialize_janet_295();

    // Create a Janet symbol from the input data
    JanetSymbol symbol = janet_symbol((const char *)data, size);

    // Use the symbol in some way to ensure it is not optimized away
    const char *symbol_name = janet_csymbol(symbol);
    if (symbol_name) {
        // Print the symbol name length
        size_t length = strlen(symbol_name);
        (void)length; // Suppress unused variable warning
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

    LLVMFuzzerTestOneInput_295(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
