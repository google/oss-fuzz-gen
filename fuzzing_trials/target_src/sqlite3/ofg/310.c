#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h> // Added for malloc and free
#include <sqlite3.h>

int LLVMFuzzerTestOneInput_310(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to be split into two strings
    if (size < 3) { // Ensure there is enough data for meaningful URI and parameter
        return 0;
    }

    // Split the input data into two parts for the URI and parameter name
    size_t uri_len = size / 2;
    size_t param_len = size - uri_len;

    // Allocate memory for the URI and parameter name strings
    char *uri = (char *)malloc(uri_len + 1);
    char *param = (char *)malloc(param_len + 1);

    if (uri == NULL || param == NULL) {
        // Memory allocation failed
        free(uri);
        free(param);
        return 0;
    }

    // Copy the data into the allocated strings and null-terminate them
    memcpy(uri, data, uri_len);
    uri[uri_len] = '\0';

    memcpy(param, data + uri_len, param_len);
    param[param_len] = '\0';

    // Ensure the URI starts with a valid schema to avoid immediate crashes
    if (strstr(uri, "file:") != uri && strstr(uri, "http:") != uri && strstr(uri, "https:") != uri) {
        free(uri);
        free(param);
        return 0;
    }

    // Define a default value for the third parameter
    sqlite3_int64 default_value = 0;

    // Call the function-under-test
    sqlite3_int64 result = sqlite3_uri_int64(uri, param, default_value);

    // Clean up allocated memory
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

    LLVMFuzzerTestOneInput_310(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
