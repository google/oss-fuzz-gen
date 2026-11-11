extern "C" {
    #include <stdint.h>
    #include <stdlib.h>
    #include <plist/plist.h>
}

extern "C" int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
    // Initialize plist_t object
    plist_t plist = plist_new_dict();
    if (!plist) {
        return 0;
    }

    // Add some dummy data to plist
    plist_dict_set_item(plist, "key1", plist_new_string("value1"));
    plist_dict_set_item(plist, "key2", plist_new_uint(42));

    // Define a path for access
    const char *path[] = {"key1", "key2"};
    uint32_t path_length = sizeof(path) / sizeof(path[0]);

    // Call the function-under-test
    plist_t result = plist_access_path(plist, path_length, (void *)path);

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

    LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
