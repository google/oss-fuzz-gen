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
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdarg>
#include "plist/plist.h"

static plist_t create_sample_dict() {
    plist_t dict = plist_new_dict();
    plist_dict_set_item(dict, "key1", plist_new_uint(42));
    plist_dict_set_item(dict, "key2", plist_new_string("123"));
    const char data_val[4] = {0x2A, 0x00, 0x00, 0x00};
    plist_dict_set_item(dict, "key3", plist_new_data(data_val, 4));
    return dict;
}

extern "C" int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a sample plist dictionary
    plist_t dict = create_sample_dict();

    // Fuzz plist_dict_get_uint
    uint64_t retrieved_value = plist_dict_get_uint(dict, "key1");
    retrieved_value = plist_dict_get_uint(dict, "key2");
    retrieved_value = plist_dict_get_uint(dict, "key3");
    retrieved_value = plist_dict_get_uint(dict, "nonexistent_key");

    // Fuzz plist_dict_remove_item
    plist_dict_remove_item(dict, "key1");
    plist_dict_remove_item(dict, "nonexistent_key");

    // Fuzz plist_dict_next_item
    plist_dict_iter iter = NULL;
    char* iter_key = NULL;
    plist_t iter_val = NULL;
    plist_dict_next_item(dict, &iter, &iter_key, &iter_val);
    if (iter_key) {
        free(iter_key);
    }

    // Fuzz plist_dict_get_size
    uint32_t size = plist_dict_get_size(dict);

    // Clean up
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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
