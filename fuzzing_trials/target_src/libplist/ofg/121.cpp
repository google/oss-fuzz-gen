#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include for memcpy
#include <plist/plist.h>

extern "C" {
    // Include necessary C headers, source files, functions, and code here.
}

extern "C" int LLVMFuzzerTestOneInput_121(const uint8_t *data, size_t size) {
    // Call the function-under-test
    plist_t array = plist_new_array();

    // Check if the data is not empty
    if (size > 0) {
        // Create a string from the input data
        char *str = (char *)malloc(size + 1);
        if (str == NULL) {
            plist_free(array);
            return 0;
        }
        memcpy(str, data, size);
        str[size] = '\0';

        // Create a plist string and add it to the array
        plist_t plist_str = plist_new_string(str);
        plist_array_append_item(array, plist_str);

        // Free the allocated string
        free(str);
    }

    // Cleanup: free the plist array to avoid memory leaks
    if (array != NULL) {
        plist_free(array);
    }

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

    LLVMFuzzerTestOneInput_121(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
