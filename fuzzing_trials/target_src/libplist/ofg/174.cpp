#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_174(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated to be used as a C-string
    if (size == 0) {
        return 0; // Exit early if no data is provided
    }

    char *null_terminated_data = (char *)malloc(size + 1);
    if (null_terminated_data == NULL) {
        return 0; // Exit if memory allocation fails
    }
    
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0'; // Null-terminate the string

    // Call the function-under-test with the null-terminated string
    plist_t result = plist_new_string(null_terminated_data);

    // Check if the plist string was created successfully
    if (result != NULL) {
        // Perform additional operations to increase code coverage
        char *extracted_string = NULL;
        plist_get_string_val(result, &extracted_string);
        if (extracted_string != NULL) {
            // Use the extracted string in some way to ensure coverage
            size_t extracted_length = strlen(extracted_string);
            if (extracted_length > 0) {
                // Perform additional operations to increase code coverage
                plist_t node = plist_new_string(extracted_string);
                plist_free(node);
            }
            free(extracted_string);
        }
    }

    // Clean up
    free(null_terminated_data);
    plist_free(result);

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

    LLVMFuzzerTestOneInput_174(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
