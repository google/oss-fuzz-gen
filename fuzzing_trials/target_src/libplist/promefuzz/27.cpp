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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <plist/plist.h>

extern "C" int LLVMFuzzerTestOneInput_27(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create dummy plist nodes
    plist_t uidnode = plist_new_uid(0);
    plist_t strnode = plist_new_string("");
    plist_t keynode = plist_new_string(""); // Using plist_new_string as a substitute for key node
    plist_t intnode = plist_new_int(0);

    // Compare UID node
    uint64_t cmpval_uid = 0;
    if (Size >= sizeof(uint64_t)) {
        memcpy(&cmpval_uid, Data, sizeof(uint64_t));
    }
    int uid_cmp_result = plist_uid_val_compare(uidnode, cmpval_uid);

    // Compare String node
    char cmpval_str[256] = {0};
    if (Size > 1) {
        size_t str_len = std::min(Size - 1, sizeof(cmpval_str) - 1);
        memcpy(cmpval_str, Data + 1, str_len);
        cmpval_str[str_len] = '\0'; // Ensure null-termination
    }
    int str_cmp_result = plist_string_val_compare(strnode, cmpval_str);

    // Compare Key node with size
    size_t n = (Size > 2) ? Data[2] % 256 : 0;
    int key_cmp_with_size_result = plist_key_val_compare_with_size(keynode, cmpval_str, n);

    // Compare Key node
    int key_cmp_result = plist_key_val_compare(keynode, cmpval_str);

    // Compare Int node with signed integer
    int64_t cmpval_int = 0;
    if (Size >= sizeof(int64_t)) {
        memcpy(&cmpval_int, Data, sizeof(int64_t));
    }
    int int_cmp_result = plist_int_val_compare(intnode, cmpval_int);

    // Compare Int node with unsigned integer
    uint64_t cmpval_uint = 0;
    if (Size >= sizeof(uint64_t)) {
        memcpy(&cmpval_uint, Data, sizeof(uint64_t));
    }
    int uint_cmp_result = plist_uint_val_compare(intnode, cmpval_uint);

    // Clean up
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

        LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    