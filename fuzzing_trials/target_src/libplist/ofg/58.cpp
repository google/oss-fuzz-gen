extern "C" {
    #include <plist/plist.h>
    #include <stdint.h>
    #include <stdlib.h>
    #include <string.h> // Include for memcpy
}

extern "C" int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
    // Ensure the data is not empty
    if (size == 0) {
        return 0;
    }

    // Allocate memory for a null-terminated string
    char *data_copy = (char *)malloc(size + 1);
    if (!data_copy) {
        return 0;
    }

    // Copy data and null-terminate
    memcpy(data_copy, data, size);
    data_copy[size] = '\0';

    // Create a plist node with some data
    plist_t plist = plist_new_data((const char *)data, size); // Cast data to const char* for compatibility

    // Call the function-under-test
    // Convert data_copy to uint8_t* for compatibility with the function signature
    // Ensure plist is not NULL before calling the function
    if (plist) {
        // Use the original data instead of data_copy for comparison
        int result = plist_data_val_compare_with_size(plist, data, size);
    }

    // Free the plist node and allocated memory
    plist_free(plist);
    free(data_copy);

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

    LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
