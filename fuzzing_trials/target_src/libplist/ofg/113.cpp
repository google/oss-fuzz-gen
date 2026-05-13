extern "C" {
    #include <plist/plist.h>
    #include <stdlib.h> // Include the standard library for free function
}

extern "C" int LLVMFuzzerTestOneInput_113(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Create a plist from the input data
    plist_t plist = nullptr;
    plist_from_bin((const char*)data, size, &plist);

    if (plist == nullptr) {
        return 0;
    }

    // Traverse the plist to ensure the fuzzer explores different code paths
    plist_dict_iter iter = nullptr;
    plist_dict_new_iter(plist, &iter);

    char *key = nullptr;
    plist_t val = nullptr;
    plist_dict_next_item(plist, iter, &key, &val);

    if (val && plist_get_node_type(val) == PLIST_BOOLEAN) {
        // Prepare a uint8_t variable to store the boolean value
        uint8_t bool_val = 0;

        // Call the function-under-test
        plist_get_bool_val(val, &bool_val);
    }

    // Clean up
    if (key) {
        free(key);
    }
    plist_free(plist);
    free(iter);

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

    LLVMFuzzerTestOneInput_113(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
