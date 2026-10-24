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
extern "C" {
#include "plist/plist.h"
}

#include <cstdint>
#include <cstdlib>
#include <cstring>

static void fuzz_plist_dict_get_bool(plist_t dict, const char *key) {
    uint8_t result = plist_dict_get_bool(dict, key);
}

static void fuzz_plist_dict_copy_bool(plist_t target_dict, plist_t source_dict, const char *key, const char *alt_source_key) {
    plist_err_t result = plist_dict_copy_bool(target_dict, source_dict, key, alt_source_key);
}

static plist_t fuzz_plist_new_bool(uint8_t val) {
    return plist_new_bool(val);
}

static void fuzz_plist_bool_val_is_true(plist_t boolnode) {
    int result = plist_bool_val_is_true(boolnode);
}

static void fuzz_plist_get_bool_val(plist_t node, uint8_t *val) {
    plist_get_bool_val(node, val);
}

static void fuzz_plist_set_bool_val(plist_t node, uint8_t val) {
    plist_set_bool_val(node, val);
}

extern "C" int LLVMFuzzerTestOneInput_36(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    uint8_t choice = Data[0];
    const char *key = "test_key";
    const char *alt_key = "alt_key";
    uint8_t val = Data[0] % 2;

    plist_t dict = plist_new_dict();
    plist_t boolnode = fuzz_plist_new_bool(val);

    switch (choice % 6) {
        case 0:
            fuzz_plist_dict_get_bool(dict, key);
            break;
        case 1:
            fuzz_plist_dict_copy_bool(dict, dict, key, alt_key);
            break;
        case 2:
            fuzz_plist_bool_val_is_true(boolnode);
            break;
        case 3:
            fuzz_plist_get_bool_val(boolnode, &val);
            break;
        case 4:
            fuzz_plist_set_bool_val(boolnode, val);
            break;
        case 5: {
            plist_t new_bool = fuzz_plist_new_bool(val);
            plist_free(new_bool);
            break;
        }
        default:
            break;
    }

    plist_free(boolnode);
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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
