#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

// Function prototype for the function-under-test
Janet janet_asm_decode_instruction(uint32_t);

int LLVMFuzzerTestOneInput_313(const uint8_t *data, size_t size) {
    // Ensure there is enough data to construct a uint32_t
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Interpret the first 4 bytes of the input data as a uint32_t
    uint32_t instruction = *((uint32_t *)data);

    // Initialize the Janet environment
    janet_init();

    // Call the function-under-test
    Janet result = janet_asm_decode_instruction(instruction);

    // Use the result in some way to avoid compiler optimizations removing the call
    (void)result;

    // Clean up the Janet environment
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

    LLVMFuzzerTestOneInput_313(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
