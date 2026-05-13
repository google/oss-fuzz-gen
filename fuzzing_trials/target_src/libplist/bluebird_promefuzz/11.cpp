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
#include <cstdarg>

static plist_t create_sample_dict(const uint8_t *Data, size_t Size) {
    plist_t dict = plist_new_dict();
    if (Size > 8) {
        plist_t int_node = plist_new_uint(*(reinterpret_cast<const uint64_t*>(Data)));
        plist_dict_set_item(dict, "test_key", int_node);
    }
    return dict;
}

static void fuzz_plist_access_pathv(plist_t dict) {
    // Example path with one key
    const char *path[] = {"test_key"};
    plist_t accessed_node = plist_access_path(dict, 1, path);
    (void)accessed_node; // Suppress unused variable warning
}

extern "C" int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a sample plist dictionary
    plist_t dict = create_sample_dict(Data, Size);

    // Fuzz plist_dict_get_uint
    uint64_t uint_value = plist_dict_get_uint(dict, "test_key");

    // Fuzz plist_dict_remove_item
    plist_dict_remove_item(dict, "test_key");

    // Fuzz plist_array_item_remove
    plist_t array = plist_new_array();
    plist_array_append_item(array, plist_new_uint(uint_value));
    plist_array_item_remove(plist_array_get_item(array, 0));

    // Fuzz plist_access_pathv
    fuzz_plist_access_pathv(dict);

    // Fuzz plist_dict_next_item
    plist_dict_iter iter = nullptr;
    char *next_key = nullptr;
    plist_t next_val = nullptr;
    plist_dict_next_item(dict, iter, &next_key, &next_val);
    if (next_key) {
        free(next_key);
    }

    // Fuzz plist_dict_get_size
    uint32_t dict_size = plist_dict_get_size(dict);

    // Clean up
    plist_free(dict);
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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
