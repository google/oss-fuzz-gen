#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_367(const uint8_t *data, size_t size) {
    // Ensure the data is not empty
    if (size == 0) {
        return 0;
    }

    // Initialize Janet
    janet_init();

    // Initialize JanetTable
    JanetTable *env = janet_table(10);
    if (!env) {
        janet_deinit();
        return 0;
    }

    // Create a null-terminated string from the input data
    char *prefix = (char *)malloc(size + 1);
    if (!prefix) {
        janet_deinit();
        return 0;
    }
    memcpy(prefix, data, size);
    prefix[size] = '\0';

    // Create a dummy JanetReg array
    JanetReg regs[] = {
        {NULL, NULL, 0, NULL}
    };

    // Check if the prefix is a valid Janet symbol
    if (janet_csymbol(prefix)) {
        // Call the function-under-test if prefix is a valid Janet symbol
        janet_cfuns_prefix(env, prefix, regs);
    }

    // Clean up
    free(prefix);

    // Deinitialize Janet
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

    LLVMFuzzerTestOneInput_367(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
