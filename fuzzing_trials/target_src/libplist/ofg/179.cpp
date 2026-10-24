extern "C" {
#include <plist/plist.h>
#include <stdlib.h>
#include <string.h>
}

extern "C" int LLVMFuzzerTestOneInput_179(const uint8_t *data, size_t size) {
    // Initialize plist_t variable
    plist_t plist = plist_new_array();
    
    // Initialize plist_array_iter variable
    plist_array_iter iter;
    
    // Ensure the data is not empty to simulate some input
    if (size > 0) {
        // Create a temporary plist string to add to the array
        char *temp_str = (char *)malloc(size + 1);
        if (temp_str != NULL) {
            memcpy(temp_str, data, size);
            temp_str[size] = '\0'; // Null-terminate the string

            // Add the string to the plist array
            plist_t string_node = plist_new_string(temp_str);
            plist_array_append_item(plist, string_node);
            
            // Free the temporary string
            free(temp_str);
        }
    }

    // Call the function-under-test
    plist_array_new_iter(plist, &iter);

    // Clean up
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

    LLVMFuzzerTestOneInput_179(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
