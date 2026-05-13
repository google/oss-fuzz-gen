#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

// Function to validate if the input can be a valid Janet symbol
int is_valid_janet_symbol(const char *str, size_t size) {
    // Janet symbols must be valid UTF-8 and cannot contain null bytes
    for (size_t i = 0; i < size; i++) {
        if (str[i] == '\0') {
            return 0; // Invalid if there's a null byte
        }
    }
    return 1; // Valid if no null byte is found
}

int LLVMFuzzerTestOneInput_583(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Check if the input size is valid and non-zero
    if (size == 0) {
        janet_deinit();
        return 0; // Exit early if there's no data to process
    }

    // Ensure the input data is null-terminated for use as a C string
    char *cstr = (char *)malloc(size + 1);
    if (cstr == NULL) {
        janet_deinit();
        return 0; // Exit if memory allocation fails
    }
    memcpy(cstr, data, size);
    cstr[size] = '\0'; // Null-terminate the string

    // Validate if the input can be a valid Janet symbol
    if (!is_valid_janet_symbol(cstr, size)) {
        free(cstr);
        janet_deinit();
        return 0; // Exit if the input is not a valid Janet symbol
    }

    // Call the function-under-test
    JanetSymbol symbol = janet_csymbol(cstr);

    // Use the symbol to prevent unused variable warning and to simulate usage
    if (symbol != NULL) {
        // Simulate usage of the symbol to ensure it is robustly tested
        const uint8_t *symbol_name = janet_symbol(cstr, size);
        if (symbol_name != NULL) {
            printf("Symbol created: %s\n", symbol_name);
        }
    }

    // Clean up
    free(cstr);
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

    LLVMFuzzerTestOneInput_583(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
