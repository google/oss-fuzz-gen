#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h> // Include for malloc and free
#include "janet.h" // Assuming this is the correct header file for the Janet library

int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet) + sizeof(int32_t) + 1) {
        return 0;
    }

    // Initialize Janet pointer
    Janet janet_obj;
    memset(&janet_obj, 0, sizeof(Janet)); // Ensure Janet object is zero-initialized
    memcpy(&janet_obj, data, sizeof(Janet));
    const Janet *janet_ptr = &janet_obj;

    // Initialize int32_t parameter
    int32_t index = *(const int32_t *)(data + sizeof(Janet));

    // Validate index if necessary (depends on janet_getflags expectations)
    // Example: index = index % MAX_INDEX; // Assuming MAX_INDEX is a valid range

    // Initialize string parameter
    const char *str = (const char *)(data + sizeof(Janet) + sizeof(int32_t));

    // Ensure the string is null-terminated
    size_t str_size = size - sizeof(Janet) - sizeof(int32_t);
    char *null_terminated_str = (char *)malloc(str_size + 1);
    if (!null_terminated_str) {
        return 0;
    }
    memcpy(null_terminated_str, str, str_size);
    null_terminated_str[str_size] = '\0';

    // Ensure the Janet object is valid before using it
    if (!janet_checktype(janet_obj, JANET_STRUCT)) { // Corrected type check
        free(null_terminated_str);
        return 0;
    }

    // Call the function-under-test
    uint64_t result = janet_getflags(janet_ptr, index, null_terminated_str);

    // Free allocated memory
    free(null_terminated_str);

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

    LLVMFuzzerTestOneInput_32(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
