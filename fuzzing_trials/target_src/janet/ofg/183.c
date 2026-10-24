#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

// Assuming the Janet type is defined as follows:
typedef struct {
    int32_t type;  // Just a placeholder for the type
    union {
        int16_t int16_value;
        // Other possible types...
    } data;
} Janet;

// Function-under-test
int16_t janet_getinteger16(const Janet *janet, int32_t index);

// Fuzzing harness
int LLVMFuzzerTestOneInput_183(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet)) {
        return 0; // Not enough data to form a Janet object
    }

    // Initialize a Janet object from the input data
    Janet janet;
    memcpy(&janet, data, sizeof(Janet));

    // Ensure the index is within a valid range
    int32_t index = 0;
    if (size >= sizeof(Janet) + sizeof(int32_t)) {
        memcpy(&index, data + sizeof(Janet), sizeof(int32_t));
    }

    // Validate the type before calling the function-under-test
    if (janet.type != 0) {
        return 0; // Return if the type is not what we expect
    }

    // Call the function-under-test
    int16_t result = janet_getinteger16(&janet, index);

    // Use the result in some way to prevent compiler optimizations from removing the call
    printf("Result: %d\n", result);

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

    LLVMFuzzerTestOneInput_183(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
