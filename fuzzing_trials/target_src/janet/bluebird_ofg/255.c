#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"
#include <string.h>
#include <stdlib.h>

// Ensure that the Janet library is initialized
void initialize_janet_255() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

extern int64_t janet_optinteger64(const Janet *argv, int32_t n, int32_t argc, int64_t def);

int LLVMFuzzerTestOneInput_255(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract the necessary values
    if (size < sizeof(Janet) * 10 + sizeof(int32_t) * 2 + sizeof(int64_t)) {
        return 0;
    }

    // Initialize the Janet library
    initialize_janet_255();

    // Allocate memory for Janet array and copy data into it
    Janet argv[10];
    for (int i = 0; i < 10; i++) {
        argv[i] = janet_wrap_integer((int32_t)data[i]); // Wrap data as Janet integers
    }

    // Ensure n and argc are within reasonable bounds and within the data size
    int32_t n = (int32_t)data[sizeof(Janet) * 10];
    int32_t argc = (int32_t)data[sizeof(Janet) * 10 + sizeof(int32_t)];

    // Limit n and argc to ensure they are valid indices within the argv array
    n = abs(n % 10); // Ensure non-negative and within bounds
    argc = abs(argc % 10); // Ensure non-negative and within bounds

    // Extract the default value
    int64_t def;
    memcpy(&def, data + sizeof(Janet) * 10 + sizeof(int32_t) * 2, sizeof(int64_t));

    // Call the function-under-test
    int64_t result = janet_optinteger64(argv, n, argc, def);

    // Use the result in some way to prevent the compiler from optimizing it out
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

    LLVMFuzzerTestOneInput_255(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
