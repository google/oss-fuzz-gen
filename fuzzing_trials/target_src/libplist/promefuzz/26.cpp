// This fuzz driver is generated for library libplist, aiming to fuzz the following functions:
// plist_new_real at plist.c:640:9 in plist.h
// plist_set_real_val at plist.c:2046:6 in plist.h
// plist_get_real_val at plist.c:1824:6 in plist.h
// plist_real_val_compare at plist.c:2147:5 in plist.h
// plist_free at plist.c:712:6 in plist.h
// plist_new_real at plist.c:640:9 in plist.h
// plist_set_int_val at plist.c:2036:6 in plist.h
// plist_int_val_compare at plist.c:2093:5 in plist.h
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

extern "C" int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double) + sizeof(int64_t)) {
        return 0;
    }

    double real_val;
    int64_t int_val;
    memcpy(&real_val, Data, sizeof(double));
    memcpy(&int_val, Data + sizeof(double), sizeof(int64_t));

    // Create and manipulate PLIST_REAL node
    plist_t real_node = plist_new_real(real_val);
    if (real_node) {
        plist_set_real_val(real_node, real_val);
        double retrieved_real_val;
        plist_get_real_val(real_node, &retrieved_real_val);
        plist_real_val_compare(real_node, real_val + 1.0);
        plist_free(real_node);
    }

    // Create and manipulate PLIST_INT node
    plist_t int_node = plist_new_real(0.0); // Use plist_new_real to create a node
    if (int_node) {
        plist_set_int_val(int_node, int_val);
        plist_int_val_compare(int_node, int_val + 1);
        plist_free(int_node);
    }

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

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    