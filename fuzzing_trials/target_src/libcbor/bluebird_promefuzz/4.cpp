#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include "cstdlib"
#include "cstdio"
#include "cstdint"
#include <cstddef>
extern "C" {
#include "cbor.h"
#include "/src/libcbor/src/cbor/floats_ctrls.h"
#include "/src/libcbor/src/cbor/common.h"
#include "/src/libcbor/src/cbor/ints.h"
}

#include "cstdio"
#include "cstdlib"

extern "C" int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there's at least one byte for meaningful fuzzing

    // Test cbor_new_null
    cbor_item_t* null_item = cbor_new_null();
    if (null_item) {
        FILE* dummy_file = fopen("./dummy_file", "w");
        if (dummy_file) {
            cbor_describe(null_item, dummy_file);
            fclose(dummy_file);
        }
        cbor_decref(&null_item);
    }

    // Test cbor_new_int8
    cbor_item_t* int8_item = cbor_new_int8();
    if (int8_item) {
        int8_item->data = (unsigned char*)malloc(1);
        if (int8_item->data) {
            int8_item->data[0] = Data[0];
            FILE* dummy_file = fopen("./dummy_file", "w");
            if (dummy_file) {
                cbor_describe(int8_item, dummy_file);
                fclose(dummy_file);
            }
        }
    }

    // Test cbor_new_int16
    cbor_item_t* int16_item = cbor_new_int16();
    if (int16_item) {
        int16_item->data = (unsigned char*)malloc(2);
        if (int16_item->data && Size >= 2) {
            int16_item->data[0] = Data[0];
            int16_item->data[1] = Data[1];
            FILE* dummy_file = fopen("./dummy_file", "w");
            if (dummy_file) {
                cbor_describe(int16_item, dummy_file);
                fclose(dummy_file);
            }
        }
    }

    // Test cbor_copy
    if (int8_item) {
        cbor_item_t* copied_item = cbor_copy(int8_item);
        if (copied_item) {
            cbor_decref(&copied_item);
        }
        cbor_decref(&int8_item);
    }

    if (int16_item) {
        cbor_decref(&int16_item);
    }

    return 0;
}