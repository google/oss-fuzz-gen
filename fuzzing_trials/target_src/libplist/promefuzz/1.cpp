// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_new_dict at plist.c:527:9 in plist.h
// plist_new_int at plist.c:614:9 in plist.h
// plist_set_int_val at plist.c:2036:6 in plist.h
// plist_get_int_val at plist.c:1807:6 in plist.h
// plist_dict_set_item at plist.c:1314:6 in plist.h
// plist_dict_get_int at plist.c:1499:9 in plist.h
// plist_new_dict at plist.c:527:9 in plist.h
// plist_dict_copy_int at plist.c:1602:13 in plist.h
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
extern "C" {
#include <plist/plist.h>
}

#include <cstdint>
#include <cstring>
#include <cstdlib>

static void fuzz_plist_functions(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    plist_t dict = plist_new_dict();
    plist_t int_node = plist_new_int(static_cast<int64_t>(Data[0]));
    plist_set_int_val(int_node, static_cast<int64_t>(Data[0]));

    int64_t retrieved_val = 0;
    plist_get_int_val(int_node, &retrieved_val);

    char key[] = "test_key";
    plist_dict_set_item(dict, key, int_node);

    int64_t dict_int_val = plist_dict_get_int(dict, key);

    plist_t target_dict = plist_new_dict();
    plist_err_t copy_result = plist_dict_copy_int(target_dict, dict, key, nullptr);

    plist_free(dict);
    plist_free(target_dict);
}

extern "C" int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    fuzz_plist_functions(Data, Size);
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

        LLVMFuzzerTestOneInput_1(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    