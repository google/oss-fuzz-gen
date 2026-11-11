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

extern "C" int LLVMFuzzerTestOneInput_40(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create dummy plist dictionaries
    plist_t source_dict = plist_new_dict();
    plist_t target_dict = plist_new_dict();

    // Create iterators
    plist_dict_iter iter = nullptr;
    plist_dict_new_iter(source_dict, &iter);
    if (iter) {
        free(iter);
    }

    // Use a key extracted from the input data
    size_t key_length = Size / 2;
    char* key = static_cast<char*>(malloc(key_length + 1));
    if (!key) {
        plist_free(source_dict);
        plist_free(target_dict);
        return 0;
    }
    memcpy(key, Data, key_length);
    key[key_length] = '\0';

    // Use an alternative key extracted from the input data
    char* alt_key = static_cast<char*>(malloc(Size - key_length + 1));
    if (!alt_key) {
        free(key);
        plist_free(source_dict);
        plist_free(target_dict);
        return 0;
    }
    memcpy(alt_key, Data + key_length, Size - key_length);
    alt_key[Size - key_length] = '\0';

    // Fuzz plist_dict_copy_item
    plist_dict_copy_item(target_dict, source_dict, key, alt_key);

    // Fuzz plist_dict_merge
    plist_dict_merge(&target_dict, source_dict);

    // Fuzz plist_sort
    plist_sort(source_dict);

    // Fuzz plist_dict_copy_uint
    plist_dict_copy_uint(target_dict, source_dict, key, alt_key);

    // Fuzz plist_dict_copy_int
    plist_dict_copy_int(target_dict, source_dict, key, alt_key);

    // Cleanup
    free(key);
    free(alt_key);
    plist_free(source_dict);
    plist_free(target_dict);

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

    LLVMFuzzerTestOneInput_40(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
