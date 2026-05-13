#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_340(const uint8_t *data, size_t size) {
    // Ensure size is large enough to extract necessary parameters
    if (size < sizeof(Janet) + 2 * sizeof(int32_t) + sizeof(const char *)) {
        return 0;
    }

    // Initialize the parameters for janet_optcstring
    const Janet *argv = (const Janet *)data;
    int32_t argc = (int32_t)(size / sizeof(Janet)); // Assume the size is enough for multiple Janets
    int32_t n = 0; // Index to retrieve the optional string from Janet array
    const char *dflt = "default_string"; // Default string

    // Call the function-under-test
    const char *result = janet_optcstring(argv, argc, n, dflt);

    // Use the result to avoid compiler optimizations (e.g., print or log)
    (void)result; // Suppress unused variable warning

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

    LLVMFuzzerTestOneInput_340(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
