#include <stdint.h>
#include <stdlib.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_94(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Create a plist from the input data
    plist_t plist = plist_new_array();

    // Use the first 4 bytes of data to determine the index
    uint32_t index = *((uint32_t *)data);

    // Add some items to the plist array to ensure it's not empty
    for (uint32_t i = 0; i < 10; ++i) {
        plist_t item = plist_new_string("test item");
        plist_array_append_item(plist, item);
    }

    // Call the function-under-test
    plist_t item = plist_array_get_item(plist, index);

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

    LLVMFuzzerTestOneInput_94(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
