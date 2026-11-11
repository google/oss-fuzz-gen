#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_572(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for initializing JanetFuncDef
    if (size < sizeof(JanetFuncDef)) {
        return 0;
    }

    // Allocate and initialize a JanetFuncDef structure
    JanetFuncDef *func_def = (JanetFuncDef *)malloc(sizeof(JanetFuncDef));
    if (!func_def) {
        return 0;
    }

    // Initialize the JanetFuncDef structure with data from the fuzzer
    // Assuming JanetFuncDef has a fixed size and can be initialized directly from data
    memcpy(func_def, data, sizeof(JanetFuncDef));

    // Ensure the function definition is valid before calling janet_thunk
    // We need to check all necessary fields that janet_thunk might use
    if (func_def->bytecode == NULL || func_def->bytecode_length == 0 || 
        func_def->constants == NULL || func_def->constants_length == 0) {
        free(func_def);
        return 0;
    }

    // Initialize the Janet runtime
    janet_init();

    // Validate that the bytecode and constants are within the bounds of the input data
    if (func_def->bytecode_length > size || func_def->constants_length > size) {
        janet_deinit();
        free(func_def);
        return 0;
    }

    // Call the function-under-test
    JanetFunction *result = janet_thunk(func_def);

    // Check if the result is valid
    if (result == NULL) {
        janet_deinit();
        free(func_def);
        return 0;
    }

    // Clean up
    janet_deinit();
    free(func_def);

    // Return 0 to indicate successful execution
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

    LLVMFuzzerTestOneInput_572(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
