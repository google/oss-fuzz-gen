#include <stddef.h>
#include <stdint.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h> // Include the necessary header for malloc

// Define a helper function to ensure null-terminated strings
static char *create_null_terminated_string(const uint8_t *data, size_t size) {
    char *str = (char *)malloc(size + 1);
    if (str != NULL) {
        memcpy(str, data, size);
        str[size] = '\0'; // Null-terminate the string
    }
    return str;
}

int LLVMFuzzerTestOneInput_295(const uint8_t *data, size_t size) {
    if (size < 3) {
        return 0; // Ensure there's enough data for at least one character in each string
    }

    // Split the input data into two parts for two strings
    size_t first_part_size = size / 2;
    size_t second_part_size = size - first_part_size;

    // Ensure each part has at least one character
    if (first_part_size == 0 || second_part_size == 0) {
        return 0;
    }

    // Create null-terminated strings from the input data
    char *uri = create_null_terminated_string(data, first_part_size);
    char *parameter = create_null_terminated_string(data + first_part_size, second_part_size);

    if (uri != NULL && parameter != NULL) {
        // Check if the URI is valid for sqlite3_uri_parameter
        if (strstr(uri, "file:") == uri || strstr(uri, "http:") == uri || strstr(uri, "https:") == uri) {
            // Call the function-under-test
            const char *result = sqlite3_uri_parameter(uri, parameter);

            // Use the result to prevent it from being optimized away
            if (result != NULL) {
                volatile char first_char = result[0];
                (void)first_char;
            }
        }
    }

    // Free allocated memory
    free(uri);
    free(parameter);

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

    LLVMFuzzerTestOneInput_295(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
