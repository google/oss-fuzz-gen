// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_new_uid at plist.c:627:9 in plist.h
// plist_new_string at plist.c:569:9 in plist.h
// plist_new_string at plist.c:569:9 in plist.h
// plist_new_int at plist.c:614:9 in plist.h
// plist_uid_val_compare at plist.c:2129:5 in plist.h
// plist_string_val_compare at plist.c:2224:5 in plist.h
// plist_key_val_compare_with_size at plist.c:2260:5 in plist.h
// plist_key_val_compare at plist.c:2251:5 in plist.h
// plist_int_val_compare at plist.c:2093:5 in plist.h
// plist_uint_val_compare at plist.c:2111:5 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_free at plist.c:712:6 in plist.h
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
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_28(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Ensure null-terminated string for plist_new_string
    std::vector<char> safeString(Data, Data + Size);
    safeString.push_back('\0');

    // Create dummy plist nodes for testing
    plist_t uidnode = plist_new_uid(Size > 7 ? *reinterpret_cast<const uint64_t*>(Data) : 0);
    plist_t strnode = plist_new_string(safeString.data());
    plist_t keynode = plist_new_string(safeString.data()); // Use plist_new_string for keynode
    plist_t intnode = plist_new_int(Size > 7 ? *reinterpret_cast<const int64_t*>(Data) : 0);

    // Prepare comparison values
    uint64_t cmpval_uint64 = Size > 7 ? *reinterpret_cast<const uint64_t*>(Data) : 0;
    int64_t cmpval_int64 = Size > 7 ? *reinterpret_cast<const int64_t*>(Data) : 0;
    const char* cmpval_str = safeString.data();

    // Fuzz plist_uid_val_compare
    plist_uid_val_compare(uidnode, cmpval_uint64);

    // Fuzz plist_string_val_compare
    plist_string_val_compare(strnode, cmpval_str);

    // Fuzz plist_key_val_compare_with_size
    plist_key_val_compare_with_size(keynode, cmpval_str, Size);

    // Fuzz plist_key_val_compare
    plist_key_val_compare(keynode, cmpval_str);

    // Fuzz plist_int_val_compare
    plist_int_val_compare(intnode, cmpval_int64);

    // Fuzz plist_uint_val_compare
    plist_uint_val_compare(intnode, cmpval_uint64);

    // Free the plist nodes
    plist_free(uidnode);
    plist_free(strnode);
    plist_free(keynode);
    plist_free(intnode);

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

        LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    