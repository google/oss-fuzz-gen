#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "plist/plist.h"

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for a null-terminated string
    if (size < 1) {
        return 0;
    }

    // Create a plist node
    plist_t node = plist_new_string("");

    // Copy data to a new buffer and ensure null-termination
    char *str = (char *)malloc(size + 1);
    if (str == NULL) {
        plist_free(node);
        return 0;
    }
    memcpy(str, data, size);
    str[size] = '\0';

    // Call the function-under-test
    plist_set_string_val(node, str);

    // Additional code to increase code coverage
    char *retrieved_str = NULL;
    plist_get_string_val(node, &retrieved_str);
    if (retrieved_str) {
        // Perform some operations on the retrieved string to ensure it's used
        size_t retrieved_len = strlen(retrieved_str);
        if (retrieved_len > 0) {
            // Do something with the retrieved string to increase coverage
            // For example, check if it matches the original string
            if (strcmp(retrieved_str, str) == 0) {
                // Strings match, this is an expected case
            }
        }
        free(retrieved_str);
    }

    // Clean up
    free(str);
    plist_free(node);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
