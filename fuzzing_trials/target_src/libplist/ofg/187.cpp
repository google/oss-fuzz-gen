#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <plist/plist.h>

extern "C" {
    #include <stdlib.h> // Include the standard library for malloc and free

    int plist_string_val_compare_with_size(plist_t node, const char *val, size_t len);
}

extern "C" int LLVMFuzzerTestOneInput_187(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to create a valid string
    if (size < 1) {
        return 0;
    }

    // Create a plist node with a string value
    plist_t node = plist_new_string("example");

    // Use the first part of the data as a string for comparison
    char *val = (char *)malloc(size + 1);
    memcpy(val, data, size);
    val[size] = '\0'; // Ensure null-termination

    // Call the function under test
    plist_string_val_compare_with_size(node, val, size);

    // Clean up
    plist_free(node);
    free(val);

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

    LLVMFuzzerTestOneInput_187(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
