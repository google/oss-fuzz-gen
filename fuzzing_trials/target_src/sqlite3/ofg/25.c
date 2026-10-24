#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>  // Include stdlib.h for malloc and free
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    // Ensure that the input data is large enough to create two strings
    if (size < 3) {  // Ensure there's enough data to create meaningful strings
        return 0;
    }

    // Find a midpoint to divide the input data into two strings
    size_t mid = size / 2;

    // Allocate memory for the two strings and ensure null-termination
    char *uri = (char *)malloc(mid + 1);
    char *param = (char *)malloc(size - mid + 1);

    if (uri == NULL || param == NULL) {
        free(uri);
        free(param);
        return 0;
    }

    // Copy data into the strings and null-terminate them
    memcpy(uri, data, mid);
    uri[mid] = '\0';

    memcpy(param, data + mid, size - mid);
    param[size - mid] = '\0';

    // Define a default boolean value
    int default_value = 1;

    // Check if uri and param are valid strings for sqlite3_uri_boolean
    if (strlen(uri) > 0 && strlen(param) > 0) {
        // Ensure that the URI starts with a valid SQLite URI prefix
        if (strncmp(uri, "file:", 5) == 0 || strncmp(uri, "http:", 5) == 0 || strncmp(uri, "https:", 6) == 0) {
            // Call the function under test
            int result = sqlite3_uri_boolean(uri, param, default_value);
        }
    }

    // Free the allocated memory
    free(uri);
    free(param);

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

    LLVMFuzzerTestOneInput_25(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
