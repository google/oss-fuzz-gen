extern "C" {
#include <plist/plist.h>
#include <stdlib.h> // Include the standard library for 'free'
}

extern "C" int LLVMFuzzerTestOneInput_66(const uint8_t *data, size_t size) {
    // Initialize plist
    plist_t plist = plist_new_dict();
    plist_dict_iter iter = NULL;
    char *key = NULL;
    plist_t val = NULL;

    // Add some dummy data to plist to ensure it's not empty
    plist_dict_set_item(plist, "key1", plist_new_string("value1"));
    plist_dict_set_item(plist, "key2", plist_new_string("value2"));

    // Initialize the iterator
    plist_dict_new_iter(plist, &iter);

    // Call the function-under-test
    plist_dict_next_item(plist, iter, &key, &val);

    // Clean up
    if (key) {
        free(key);
    }
    if (val) {
        plist_free(val);
    }
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

    LLVMFuzzerTestOneInput_66(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
