#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h" // Assuming this is the correct header file for Janet

int LLVMFuzzerTestOneInput_246(const uint8_t *data, size_t size) {
    // Initialize the Janet library
    janet_init();

    // Ensure the size is large enough to split into a string and a Janet value
    if (size < 2) {
        janet_deinit();
        return 0;
    }

    // Split the input data into two parts: a string and a Janet value
    size_t str_len = size / 2;
    size_t janet_data_len = size - str_len;

    // Allocate memory for the string and ensure it's null-terminated
    char *str = (char *)malloc(str_len + 1);
    if (str == NULL) {
        janet_deinit();
        return 0;
    }
    memcpy(str, data, str_len);
    str[str_len] = '\0';

    // Create a Janet value from the remaining data
    Janet janet_value;
    if (janet_data_len > 0) {
        janet_value = janet_wrap_string(janet_string(data + str_len, janet_data_len));
    } else {
        janet_value = janet_wrap_nil();
    }

    // Call the function-under-test
    // Ensure the string is a valid Janet symbol or key
    if (janet_csymbol(str)) {
        janet_setdyn(str, janet_value);
    }

    // Free allocated memory
    free(str);

    // Deinitialize the Janet library
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

    LLVMFuzzerTestOneInput_246(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
