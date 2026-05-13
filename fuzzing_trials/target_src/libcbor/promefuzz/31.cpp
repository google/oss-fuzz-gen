// This fuzz driver is generated for library libcbor, aiming to fuzz the following functions:
// cbor_serialize_float_ctrl at serialization.c:377:8 in serialization.h
// cbor_float_get_float at floats_ctrls.c:46:8 in floats_ctrls.h
// cbor_encode_single at encoding.c:180:8 in encoding.h
// cbor_encode_double at encoding.c:195:8 in encoding.h
// cbor_encode_half at encoding.c:130:8 in encoding.h
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <cstddef>
#include <cstdint>
#include <cmath>
#include "cbor.h"
#include "cbor.h"
#include "cbor.h"
#include "cbor.h"

extern "C" int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(float)) return 0;

    // Prepare a dummy cbor_item_t
    cbor_item_t item;
    item.type = CBOR_TYPE_FLOAT_CTRL;
    item.refcount = 1;
    item.data = const_cast<unsigned char*>(Data);

    // 1. Test cbor_is_float
    bool is_float = cbor_is_float(&item);

    // 2. Test cbor_serialize_float_ctrl
    unsigned char buffer[128];
    size_t serialized_length = cbor_serialize_float_ctrl(&item, buffer, sizeof(buffer));

    // 3. Test cbor_float_get_float
    double float_value = cbor_float_get_float(&item);

    // 4. Test cbor_encode_single
    float single_value;
    std::memcpy(&single_value, Data, sizeof(float));
    size_t single_encoded_length = cbor_encode_single(single_value, buffer, sizeof(buffer));

    // 5. Test cbor_encode_double
    if (Size >= sizeof(double)) {
        double double_value;
        std::memcpy(&double_value, Data, sizeof(double));
        size_t double_encoded_length = cbor_encode_double(double_value, buffer, sizeof(buffer));
    }

    // 6. Test cbor_encode_half
    size_t half_encoded_length = cbor_encode_half(single_value, buffer, sizeof(buffer));

    return 0;
}