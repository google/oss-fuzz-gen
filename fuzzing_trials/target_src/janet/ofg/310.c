#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "janet.h" // Assuming janet.h is the header file where Janet type is defined

int janet_symeq(Janet j, const char *str);

int LLVMFuzzerTestOneInput_310(const uint8_t *data, size_t size) {
    // Ensure the data size is at least 1 to create a valid string
    if (size < 1) {
        return 0;
    }

    // Initialize a Janet value
    Janet janet_value = janet_wrap_nil(); // Assuming janet_wrap_nil() is a way to initialize a Janet type

    // Create a null-terminated string from the input data
    char *input_str = (char *)malloc(size + 1);
    if (input_str == NULL) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(input_str, data, size);
    input_str[size] = '\0';

    // Call the function-under-test
    int result = janet_symeq(janet_value, input_str);

    // Cleanup
    free(input_str);

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

    LLVMFuzzerTestOneInput_310(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
