#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for at least two strings and an integer
    if (size < 3) {
        return 0;
    }

    // Find two null-terminated strings within the data
    size_t first_str_len = strnlen((const char *)data, size);
    if (first_str_len == size) {
        return 0; // No null-terminator found for the first string
    }

    const char *uri = (const char *)data;
    const char *param = (const char *)(data + first_str_len + 1);

    // Calculate remaining size after the first string
    size_t remaining_size = size - (first_str_len + 1);
    size_t second_str_len = strnlen(param, remaining_size);
    if (second_str_len == remaining_size) {
        return 0; // No null-terminator found for the second string
    }

    // Calculate the offset for the integer
    size_t int_offset = first_str_len + 1 + second_str_len + 1;
    if (int_offset + sizeof(int) > size) {
        return 0; // Not enough space for the integer
    }

    // Extract the integer value
    int default_value = *(int *)(data + int_offset);

    // Call the function-under-test
    int result = sqlite3_uri_boolean(uri, param, default_value);

    // Use the result in some way (here we just suppress unused variable warning)
    (void)result;

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_24(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
