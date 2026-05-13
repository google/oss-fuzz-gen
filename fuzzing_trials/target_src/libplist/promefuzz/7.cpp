// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_dict_copy_data at plist.c:1622:13 in plist.h
// plist_dict_copy_item at plist.c:1582:13 in plist.h
// plist_dict_copy_bool at plist.c:1592:13 in plist.h
// plist_dict_copy_uint at plist.c:1612:13 in plist.h
// plist_dict_copy_int at plist.c:1602:13 in plist.h
// plist_dict_copy_string at plist.c:1632:13 in plist.h
// plist_new_dict at plist.c:527:9 in plist.h
// plist_new_dict at plist.c:527:9 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_free at plist.c:712:6 in plist.h
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
#include <plist/plist.h>

static void fuzz_plist_dict_copy_data(plist_t target_dict, plist_t source_dict, const char *key, const char *alt_source_key) {
    plist_dict_copy_data(target_dict, source_dict, key, alt_source_key);
}

static void fuzz_plist_dict_copy_item(plist_t target_dict, plist_t source_dict, const char *key, const char *alt_source_key) {
    plist_dict_copy_item(target_dict, source_dict, key, alt_source_key);
}

static void fuzz_plist_dict_copy_bool(plist_t target_dict, plist_t source_dict, const char *key, const char *alt_source_key) {
    plist_dict_copy_bool(target_dict, source_dict, key, alt_source_key);
}

static void fuzz_plist_dict_copy_uint(plist_t target_dict, plist_t source_dict, const char *key, const char *alt_source_key) {
    plist_dict_copy_uint(target_dict, source_dict, key, alt_source_key);
}

static void fuzz_plist_dict_copy_int(plist_t target_dict, plist_t source_dict, const char *key, const char *alt_source_key) {
    plist_dict_copy_int(target_dict, source_dict, key, alt_source_key);
}

static void fuzz_plist_dict_copy_string(plist_t target_dict, plist_t source_dict, const char *key, const char *alt_source_key) {
    plist_dict_copy_string(target_dict, source_dict, key, alt_source_key);
}

extern "C" int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;

    // Create dictionaries
    plist_t target_dict = plist_new_dict();
    plist_t source_dict = plist_new_dict();

    // Ensure null-terminated strings for keys
    std::vector<char> key_vec(Data, Data + std::min(Size, static_cast<size_t>(2)));
    key_vec.push_back('\0');
    const char *key = key_vec.data();

    std::vector<char> alt_key_vec(Data + 2, Data + std::min(Size, static_cast<size_t>(4)));
    alt_key_vec.push_back('\0');
    const char *alt_source_key = alt_key_vec.data();

    // Fuzz various functions
    fuzz_plist_dict_copy_data(target_dict, source_dict, key, alt_source_key);
    fuzz_plist_dict_copy_item(target_dict, source_dict, key, alt_source_key);
    fuzz_plist_dict_copy_bool(target_dict, source_dict, key, alt_source_key);
    fuzz_plist_dict_copy_uint(target_dict, source_dict, key, alt_source_key);
    fuzz_plist_dict_copy_int(target_dict, source_dict, key, alt_source_key);
    fuzz_plist_dict_copy_string(target_dict, source_dict, key, alt_source_key);

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

        LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    