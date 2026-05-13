#include <stdint.h>
#include <stddef.h>
#include <string.h> // Include the library for memcpy

extern "C" {
    #include <plist/plist.h>

    int plist_int_val_is_negative(plist_t node);
}

extern "C" int LLVMFuzzerTestOneInput_118(const uint8_t *data, size_t size) {
    // Initialize a plist node
    plist_t node = NULL;

    // Create a new plist node of type integer
    node = plist_new_int(0);

    // If there's data, use it to set the integer value of the node
    if (size >= sizeof(int64_t)) {
        int64_t value;
        memcpy(&value, data, sizeof(int64_t));
        plist_set_int_val(node, value);
    } else {
        // Set a default non-negative value if data is insufficient
        plist_set_int_val(node, 1);
    }

    // Call the function-under-test
    int result = plist_int_val_is_negative(node);

    // Free the plist node
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

    LLVMFuzzerTestOneInput_118(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
