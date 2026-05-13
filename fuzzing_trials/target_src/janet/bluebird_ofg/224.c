#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h" // Ensure the correct path for janet.h

int LLVMFuzzerTestOneInput_224(const uint8_t *data, size_t size) {
    // Check if size is 0 to avoid unnecessary operations
    if (size == 0) {
        return 0;
    }

    // Allocate memory for a null-terminated string
    char *input = (char *)malloc(size + 1);
    if (input == NULL) {
        return 0;
    }
    
    // Copy the data into the input buffer and null-terminate it
    memcpy(input, data, size);
    input[size] = '\0';

    // Initialize the Janet environment
    janet_init();

    // Check if the input is valid or meets certain criteria before calling the function
    // This is a placeholder for any specific checks needed
    if (input[0] != '\0') {
        // Call the function-under-test
        Janet result = janet_resolve_core(input);
        
        // Use janet_truthy to check the result
        if (janet_truthy(result)) {
            // Perform operations based on the result
            // For example, print the result or handle it in a specific way
            const uint8_t *result_str = janet_to_string(result);
            printf("Result is truthy: %s\n", result_str);
        }
    }

    // Clean up the Janet environment
    janet_deinit();

    // Free the allocated memory
    free(input);

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

    LLVMFuzzerTestOneInput_224(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
