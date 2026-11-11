// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_new_string at plist.c:569:9 in plist.h
// plist_new_string at plist.c:569:9 in plist.h
// plist_string_val_compare at plist.c:2224:5 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_key_val_compare_with_size at plist.c:2260:5 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_key_val_compare at plist.c:2251:5 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_string_val_compare_with_size at plist.c:2233:5 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_key_val_contains at plist.c:2269:5 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_compare_node_value at plist.c:1949:6 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_free at plist.c:712:6 in plist.h
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <plist/plist.h>
#include <cstdint>
#include <cstring>
#include <cstdlib>

static plist_t create_string_node(const char* value) {
    return plist_new_string(value);
}

static plist_t create_key_node(const char* value) {
    // plist_new_key does not exist, use plist_new_string for key simulation
    return plist_new_string(value);
}

static void fuzz_plist_string_val_compare(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    char* cmpval = new char[Size + 1];
    memcpy(cmpval, Data, Size);
    cmpval[Size] = '\0';
    plist_t strnode = create_string_node(cmpval);
    plist_string_val_compare(strnode, cmpval);
    plist_free(strnode);
    delete[] cmpval;
}

static void fuzz_plist_key_val_compare_with_size(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;
    char* cmpval = new char[Size + 1];
    memcpy(cmpval, Data, Size);
    cmpval[Size] = '\0';
    size_t n = Data[Size - 1];
    plist_t keynode = create_key_node(cmpval);
    plist_key_val_compare_with_size(keynode, cmpval, n);
    plist_free(keynode);
    delete[] cmpval;
}

static void fuzz_plist_key_val_compare(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    char* cmpval = new char[Size + 1];
    memcpy(cmpval, Data, Size);
    cmpval[Size] = '\0';
    plist_t keynode = create_key_node(cmpval);
    plist_key_val_compare(keynode, cmpval);
    plist_free(keynode);
    delete[] cmpval;
}

static void fuzz_plist_string_val_compare_with_size(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;
    char* cmpval = new char[Size + 1];
    memcpy(cmpval, Data, Size);
    cmpval[Size] = '\0';
    size_t n = Data[Size - 1];
    plist_t strnode = create_string_node(cmpval);
    plist_string_val_compare_with_size(strnode, cmpval, n);
    plist_free(strnode);
    delete[] cmpval;
}

static void fuzz_plist_key_val_contains(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;
    char* substr = new char[Size + 1];
    memcpy(substr, Data, Size);
    substr[Size] = '\0';
    plist_t keynode = create_key_node(substr);
    plist_key_val_contains(keynode, substr);
    plist_free(keynode);
    delete[] substr;
}

static void fuzz_plist_compare_node_value(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;
    char* value1 = new char[Size / 2 + 1];
    char* value2 = new char[Size / 2 + 1];
    memcpy(value1, Data, Size / 2);
    value1[Size / 2] = '\0';
    memcpy(value2, Data + Size / 2, Size / 2);
    value2[Size / 2] = '\0';
    plist_t node_l = create_string_node(value1);
    plist_t node_r = create_string_node(value2);
    plist_compare_node_value(node_l, node_r);
    plist_free(node_l);
    plist_free(node_r);
    delete[] value1;
    delete[] value2;
}

extern "C" int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    fuzz_plist_string_val_compare(Data, Size);
    fuzz_plist_key_val_compare_with_size(Data, Size);
    fuzz_plist_key_val_compare(Data, Size);
    fuzz_plist_string_val_compare_with_size(Data, Size);
    fuzz_plist_key_val_contains(Data, Size);
    fuzz_plist_compare_node_value(Data, Size);
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

        LLVMFuzzerTestOneInput_14(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    