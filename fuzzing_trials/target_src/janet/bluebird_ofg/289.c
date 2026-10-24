#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

// Function signature for the function-under-test
Janet janet_asm_decode_instruction(uint32_t);

int LLVMFuzzerTestOneInput_289(const uint8_t *data, size_t size) {
    // Ensure that there is enough data to read a uint32_t
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Initialize the Janet VM
    janet_init();

    // Read the first 4 bytes as a uint32_t for the instruction
    uint32_t instruction = *(const uint32_t *)data;

    // Call the function-under-test
    Janet result = janet_asm_decode_instruction(instruction);

    // Use the result in some way to avoid compiler optimizations
    // Here, we simply check if the result is non-null
    if (janet_checktype(result, JANET_NIL)) {
        // Clean up the Janet VM before returning
        janet_deinit();
        return 0;
    }

    // Clean up the Janet VM before returning
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

    LLVMFuzzerTestOneInput_289(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
