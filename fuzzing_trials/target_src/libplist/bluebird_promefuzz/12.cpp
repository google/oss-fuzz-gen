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
#include <cstring>
#include <iostream>
#include "plist/plist.h"

static void fuzz_plist_dict_copy_data(plist_t target_dict, plist_t source_dict, const char *key, const char *alt_source_key) {
    plist_dict_copy_data(target_dict, source_dict, key, alt_source_key);
}

static void fuzz_plist_data_val_compare_with_size(plist_t datanode, const uint8_t* cmpval, size_t n) {
    plist_data_val_compare_with_size(datanode, cmpval, n);
}

static void fuzz_plist_set_data_val(plist_t node, const char *val, uint64_t length) {
    plist_set_data_val(node, val, length);
}

static plist_t fuzz_plist_new_data(const char *val, uint64_t length) {
    return plist_new_data(val, length);
}

static const char* fuzz_plist_get_data_ptr(plist_t node, uint64_t* length) {
    return plist_get_data_ptr(node, length);
}

static void fuzz_plist_get_data_val(plist_t node, char **val, uint64_t * length) {
    plist_get_data_val(node, val, length);
}

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy plist node
    plist_t dummy_node = plist_new_data(reinterpret_cast<const char*>(Data), Size);

    // Fuzz plist_dict_copy_data
    plist_t target_dict = plist_new_dict();
    plist_t source_dict = plist_new_dict();
    fuzz_plist_dict_copy_data(target_dict, source_dict, "key", nullptr);

    // Fuzz plist_data_val_compare_with_size
    fuzz_plist_data_val_compare_with_size(dummy_node, Data, Size);

    // Fuzz plist_set_data_val
    fuzz_plist_set_data_val(dummy_node, reinterpret_cast<const char*>(Data), Size);

    // Fuzz plist_new_data
    plist_t new_data_node = fuzz_plist_new_data(reinterpret_cast<const char*>(Data), Size);
    if (new_data_node) {
        plist_free(new_data_node);
    }

    // Fuzz plist_get_data_ptr
    uint64_t length = 0;
    const char* data_ptr = fuzz_plist_get_data_ptr(dummy_node, &length);

    // Fuzz plist_get_data_val
    char *val = nullptr;
    fuzz_plist_get_data_val(dummy_node, &val, &length);
    if (val) {
        plist_mem_free(val);
    }

    // Cleanup
    plist_free(dummy_node);
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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
