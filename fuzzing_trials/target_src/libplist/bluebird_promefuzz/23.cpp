#include <sys/stat.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include "plist/plist.h"
#include <cstdint>
#include <cstring>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize plist variables
    plist_t dict = plist_new_dict();
    plist_t item = plist_new_string("test_value");

    // Create a dummy file if needed
    const char *dummy_file = "./dummy_file";
    FILE *file = fopen(dummy_file, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }

    // Use plist_dict_set_item
    plist_dict_set_item(dict, "test_key", item);

    // Retrieve the item using plist_dict_get_item
    plist_t retrieved_item = plist_dict_get_item(dict, "test_key");

    // Use plist_dict_get_item_key
    char *retrieved_key = nullptr;
    plist_dict_get_item_key(retrieved_item, &retrieved_key);
    if (retrieved_key) {
        free(retrieved_key);
    }

    // Use plist_dict_get_bool
    uint8_t bool_value = plist_dict_get_bool(dict, "test_key");

    // Use plist_get_key_val
    char *key_val = nullptr;
    plist_get_key_val(item, &key_val);
    if (key_val) {
        plist_mem_free(key_val);
    }

    // Use plist_dict_remove_item
    plist_dict_remove_item(dict, "test_key");

    // Cleanup
    plist_free(dict);

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

    LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
