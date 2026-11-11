#include <stdint.h>
#include <stddef.h>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
    // Call the function-under-test
    plist_t array = plist_new_array();

    // Since plist_new_array() does not take any input and returns a new plist array,
    // there's no need to use 'data' or 'size' to influence its creation.
    // However, you can perform operations on the plist array if needed for further testing.

    // Example operation: adding an element to the array
    if (array != NULL && size > 0) {
        plist_t element = plist_new_data((const char*)data, size);
        plist_array_append_item(array, element);
    }

    // Clean up
    plist_free(array);

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

    LLVMFuzzerTestOneInput_120(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
