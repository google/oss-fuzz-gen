#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "janet.h"

// Function-under-test
void janet_setdyn(const char *name, Janet value);

int LLVMFuzzerTestOneInput_328(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to create a valid string and Janet value
    if (size < 2) {
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    // Split the data into two parts: one for the string and one for the Janet value
    size_t string_size = size / 2;
    size_t janet_size = size - string_size;

    // Create a null-terminated string from the first part of the data
    char *name = (char *)malloc(string_size + 1);
    if (!name) {
        janet_deinit();
        return 0;
    }
    memcpy(name, data, string_size);
    name[string_size] = '\0';

    // Ensure the name is not empty to avoid potential issues with janet_setdyn
    if (name[0] == '\0') {
        free(name);
        janet_deinit();
        return 0;
    }

    // Create a Janet value from the second part of the data
    Janet value;
    if (janet_size >= sizeof(int32_t)) {
        int32_t int_value;
        memcpy(&int_value, data + string_size, sizeof(int32_t));
        value = janet_wrap_integer(int_value);
    } else {
        // If not enough data for a full Janet, use a default value
        value = janet_wrap_nil();
    }

    // Call the function-under-test
    janet_setdyn(name, value);

    // Clean up
    free(name);
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

    LLVMFuzzerTestOneInput_328(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
