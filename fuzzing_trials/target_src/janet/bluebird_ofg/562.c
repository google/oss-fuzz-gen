#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

// Ensure that the Janet environment is initialized
void initialize_janet_562() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

extern uint32_t janet_optuinteger(const Janet *, int32_t, int32_t, uint32_t);

int LLVMFuzzerTestOneInput_562(const uint8_t *data, size_t size) {
    initialize_janet_562();

    if (size < sizeof(Janet) + sizeof(int32_t) * 2 + sizeof(uint32_t)) {
        return 0; // Not enough data to fill all parameters
    }

    // Initialize the parameters
    const Janet *janet_array = (const Janet *)data;
    int32_t n = *(const int32_t *)(data + sizeof(Janet));
    int32_t def = *(const int32_t *)(data + sizeof(Janet) + sizeof(int32_t));
    uint32_t lo = *(const uint32_t *)(data + sizeof(Janet) + sizeof(int32_t) * 2);

    // Ensure n is non-negative and within bounds to prevent buffer overflow
    if (n < 0 || (size_t)n > (size - sizeof(Janet)) / sizeof(Janet)) {
        return 0;
    }

    // Ensure the janet_array is valid by constructing a simple Janet array
    Janet *janet_values = janet_tuple_n(janet_array, n);

    // Call the function-under-test
    uint32_t result = janet_optuinteger(janet_values, n, def, lo);

    // Use the result in some way to prevent compiler optimizations from removing the call
    (void)result;

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

    LLVMFuzzerTestOneInput_562(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
