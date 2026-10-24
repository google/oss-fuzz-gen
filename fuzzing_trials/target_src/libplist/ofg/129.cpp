extern "C" {
#include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_129(const uint8_t *data, size_t size) {
    if (size < 2) return 0; // Ensure there's enough data for uint32_t index

    // Initialize plist_t variables
    plist_t array = plist_new_array();
    plist_t item = plist_new_string("test_item");

    // Extract a uint32_t index from the input data
    uint32_t index = 0;
    if (size >= sizeof(uint32_t)) {
        index = *((uint32_t*)data);
    }

    // Call the function-under-test
    plist_array_set_item(array, item, index);

    // Clean up
    plist_free(array);
    plist_free(item);

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

    LLVMFuzzerTestOneInput_129(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
