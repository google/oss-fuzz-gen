extern "C" {
    #include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_93(const uint8_t *data, size_t size) {
    // Initialize a plist object
    plist_t plist = plist_new_array();

    // Add some dummy data to the plist array to ensure it's not empty
    plist_t dummy_item1 = plist_new_string("item1");
    plist_t dummy_item2 = plist_new_string("item2");
    plist_array_append_item(plist, dummy_item1);
    plist_array_append_item(plist, dummy_item2);

    // Ensure the index is within the bounds of the array
    uint32_t index = 0;
    if (size > 0) {
        index = static_cast<uint32_t>(data[0] % 2); // Since we added 2 items
    }

    // Call the function-under-test
    plist_t item = plist_array_get_item(plist, index);

    // Clean up
    plist_free(item);
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

    LLVMFuzzerTestOneInput_93(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
