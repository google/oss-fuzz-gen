#include <stdint.h>
#include <stdlib.h>

extern "C" {
    #include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Initialize plist_t and plist_dict_iter
    plist_t plist = plist_new_dict();
    plist_dict_iter iter;

    // Ensure the data is not empty before proceeding
    if (size == 0) {
        return 0;
    }

    // Add some dummy key-value pairs to the plist dictionary
    plist_dict_set_item(plist, "key1", plist_new_string("value1"));
    plist_dict_set_item(plist, "key2", plist_new_string("value2"));
    plist_dict_set_item(plist, "key3", plist_new_string("value3"));

    // Call the function-under-test
    plist_dict_new_iter(plist, &iter);

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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
