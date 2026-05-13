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
#include <cstdlib>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;

    plist_t target_dict = plist_new_dict();
    plist_t source_dict = plist_new_dict();

    // Create dummy data for keys
    const char *key = "key";
    const char *alt_source_key = (Size > 4) ? "alt_key" : nullptr;

    // Add dummy data to source_dict
    plist_t data_node = plist_new_data(reinterpret_cast<const char*>(Data), Size);
    plist_dict_set_item(source_dict, key, data_node);

    // Test plist_dict_copy_data
    plist_err_t err = plist_dict_copy_data(target_dict, source_dict, key, alt_source_key);

    // Test plist_dict_copy_item
    err = plist_dict_copy_item(target_dict, source_dict, key, alt_source_key);

    // Test plist_dict_copy_uint
    plist_t uint_node = plist_new_uint(42);
    plist_dict_set_item(source_dict, key, uint_node);
    err = plist_dict_copy_uint(target_dict, source_dict, key, alt_source_key);

    // Test plist_dict_copy_int
    plist_t int_node = plist_new_int(-42);
    plist_dict_set_item(source_dict, key, int_node);
    err = plist_dict_copy_int(target_dict, source_dict, key, alt_source_key);

    // Test plist_dict_copy_string
    plist_t string_node = plist_new_string("test_string");
    plist_dict_set_item(source_dict, key, string_node);
    err = plist_dict_copy_string(target_dict, source_dict, key, alt_source_key);

    // Test libplist_version
    const char *version = libplist_version();

    // Clean up
    plist_free(target_dict);
    plist_free(source_dict);

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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
