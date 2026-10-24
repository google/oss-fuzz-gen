extern "C" {
    #include <stdint.h>
    #include <stdlib.h>
    #include <string.h>
    #include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_106(const uint8_t *data, size_t size) {
    // Ensure size is non-zero to avoid creating an empty string
    if (size == 0) {
        return 0;
    }

    // Allocate memory for a null-terminated string
    char *input_data = (char *)malloc(size + 1);
    if (input_data == NULL) {
        return 0; // Memory allocation failed
    }

    // Copy data to input_data and null-terminate it
    memcpy(input_data, data, size);
    input_data[size] = '\0';

    // Call the function-under-test
    plist_t plist = NULL;
    plist_from_xml(input_data, (uint32_t)size, &plist);

    // Check if plist is not NULL and perform operations
    if (plist != NULL) {
        // Example operation: get plist type
        plist_type type = plist_get_node_type(plist);

        // Depending on the type, perform different operations
        if (type == PLIST_STRING) {
            char *str_val = NULL;
            plist_get_string_val(plist, &str_val);
            if (str_val) {
                free(str_val);
            }
        }
        // Add more operations for different types if needed
    }

    // Clean up
    free(input_data);
    plist_free(plist);

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

    LLVMFuzzerTestOneInput_106(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
