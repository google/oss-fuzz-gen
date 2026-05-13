#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_204(const uint8_t *data, size_t size) {
    // Initialize Janet environment
    janet_init();

    // Create a JanetFuncDef structure
    JanetFuncDef funcDef;
    funcDef.name = janet_string((const uint8_t *)"fuzz_func", 9); // Corrected to use janet_string
    funcDef.source = janet_string((const uint8_t *)"fuzz_source", 11); // Corrected to use janet_string
    funcDef.bytecode = (uint32_t *)data; // Cast data to uint32_t* for bytecode
    funcDef.bytecode_length = size / sizeof(uint32_t);
    funcDef.constants = NULL; // Assuming no constants for simplicity
    funcDef.constants_length = 0;
    funcDef.slotcount = 0; // Assuming no slots for simplicity
    funcDef.flags = 0; // Assuming no flags for simplicity

    // Call the function-under-test
    Janet result = janet_disasm(&funcDef);

    // Clean up Janet environment
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

    LLVMFuzzerTestOneInput_204(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
