#include <stdint.h>
#include <string.h>
#include <janet.h>

// Fuzzing harness for janet_symeq
int LLVMFuzzerTestOneInput_311(const uint8_t *data, size_t size) {
    Janet janetValue;
    const char *str;

    // Ensure the size is large enough to contain at least one character for the string
    if (size < 2) { // Ensure there's at least one byte for integer and one for string
        return 0;
    }

    // Initialize the Janet value
    janetValue = janet_wrap_integer((int)(data[0])); // Example of wrapping an integer

    // Allocate memory for the string and ensure it is null-terminated
    char *buffer = malloc(size); // Allocate memory for the string
    if (!buffer) {
        return 0; // Return if memory allocation fails
    }
    memcpy(buffer, data + 1, size - 1);
    buffer[size - 1] = '\0'; // Null-terminate the string

    str = (const char *)buffer;

    // Call the function-under-test
    int result = janet_symeq(janetValue, str);

    // Use the result to avoid compiler optimizations (optional)
    if (result == 0) {
        free(buffer); // Free allocated memory
        return 0;
    }

    free(buffer); // Free allocated memory
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

    LLVMFuzzerTestOneInput_311(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
