#include <stdint.h>
#include <stddef.h>

extern "C" {
    #include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_83(const uint8_t *data, size_t size) {
    // Initialize a plist object
    plist_t plist = plist_new_array();

    // Add some items to the plist array for testing
    plist_array_append_item(plist, plist_new_string("Item1"));
    plist_array_append_item(plist, plist_new_string("Item2"));
    plist_array_append_item(plist, plist_new_string("Item3"));

    // Ensure there is at least one item in the array
    uint32_t count = plist_array_get_size(plist);
    if (count == 0) {
        plist_array_append_item(plist, plist_new_string("DefaultItem"));
        count = 1; // Since we added one item
    }

    // Use the input data to determine the index to remove
    uint32_t index = 0;
    if (size > 0) {
        index = data[0] % count; // Ensure index is within bounds
    }

    // Call the function-under-test
    plist_array_remove_item(plist, index);

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

    LLVMFuzzerTestOneInput_83(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
