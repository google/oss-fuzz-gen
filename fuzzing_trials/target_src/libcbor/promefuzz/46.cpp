// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_new_float8 at floats_ctrls.c:137:14 in floats_ctrls.h
// cbor_set_float8 at floats_ctrls.c:82:6 in floats_ctrls.h
// cbor_float_get_float8 at floats_ctrls.c:40:8 in floats_ctrls.h
// cbor_float_get_float at floats_ctrls.c:46:8 in floats_ctrls.h
// cbor_build_float8 at floats_ctrls.c:181:14 in floats_ctrls.h
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
#include <cmath>
#include "cbor.h"

extern "C" int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) return 0;

    // Extract a double value from the input data
    double value;
    memcpy(&value, Data, sizeof(double));

    // Test cbor_new_float8
    cbor_item_t* item = cbor_new_float8();
    if (!item) {
        return 0; // Memory allocation failed, exit the test
    }

    // Test cbor_set_float8
    cbor_set_float8(item, value);

    // Test cbor_float_get_float8
    double retrieved_value = cbor_float_get_float8(item);

    // Test cbor_float_get_float
    double general_retrieved_value = cbor_float_get_float(item);

    // Test cbor_build_float8
    cbor_item_t* built_item = cbor_build_float8(value);
    if (built_item) {
        // Cleanup the built item
        // Assuming a function exists to free cbor_item_t
        // free_cbor_item(built_item);
    }

    // Cleanup the original item
    // Assuming a function exists to free cbor_item_t
    // free_cbor_item(item);

    return 0;
}