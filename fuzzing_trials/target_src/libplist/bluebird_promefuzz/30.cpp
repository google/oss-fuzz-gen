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
#include <cstdlib>
#include <cstring>
#include "plist/plist.h"

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy plist dictionary node
    plist_t dict = plist_new_dict();
    if (!dict) return 0;

    // Create a dummy plist item node
    plist_t item = plist_new_string("dummy_value");
    if (!item) {
        plist_free(dict);
        return 0;
    }

    // Convert Data to a null-terminated string for use as a key
    char *key = static_cast<char*>(malloc(Size + 1));
    if (!key) {
        plist_free(dict);
        plist_free(item);
        return 0;
    }
    memcpy(key, Data, Size);
    key[Size] = '\0';

    // Fuzzing plist_dict_set_item
    plist_dict_set_item(dict, key, item);

    // Fuzzing plist_dict_get_item
    plist_t fetched_item = plist_dict_get_item(dict, key);

    // Fuzzing plist_dict_item_get_key
    plist_t fetched_key = plist_dict_item_get_key(fetched_item);

    // Fuzzing plist_dict_remove_item
    plist_dict_remove_item(dict, key);

    // Create an iterator
    plist_dict_iter iter = nullptr;

    // Fuzzing plist_dict_next_item
    char *next_key = nullptr;
    plist_t next_val = nullptr;
    plist_dict_next_item(dict, iter, &next_key, &next_val);
    if (next_key) {
        free(next_key);
    }

    // Fuzzing plist_dict_free_iter
    plist_dict_free_iter(iter);

    // Cleanup
    free(key);
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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
