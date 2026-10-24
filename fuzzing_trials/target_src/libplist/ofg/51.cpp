extern "C" {
    #include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_51(const uint8_t *data, size_t size) {
    // Initialize a plist object
    plist_t plist = plist_new_array();

    // Add some dummy items to the array to ensure it is not empty
    plist_array_append_item(plist, plist_new_string("item1"));
    plist_array_append_item(plist, plist_new_string("item2"));
    plist_array_append_item(plist, plist_new_string("item3"));

    // Use the data to determine which item to remove
    if (size > 0) {
        size_t index_to_remove = data[0] % plist_array_get_size(plist);
        plist_t item = plist_array_get_item(plist, index_to_remove);

        // Call the function-under-test
        plist_array_item_remove(item);
    }

    // Free the plist object
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

    LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
