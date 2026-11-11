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
#include <cstring>
#include <cmath>
#include <iostream>
#include "cbor.h"
#include "cbor.h"
#include "cbor.h"
#include "cbor.h"

extern "C" int LLVMFuzzerTestOneInput_43(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(float)) return 0;

    // Initialize a cbor_item_t with type CBOR_TYPE_FLOAT_CTRL
    cbor_item_t item;
    item.type = CBOR_TYPE_FLOAT_CTRL;
    item.refcount = 0;
    item.data = const_cast<unsigned char*>(Data);

    // Check if the item is a float
    bool isFloat = cbor_is_float(&item);

    // Prepare a buffer for serialization
    unsigned char buffer[256];
    size_t buffer_size = sizeof(buffer);

    // Serialize the float/control item
    size_t serialized_length = cbor_serialize_float_ctrl(&item, buffer, buffer_size);

    // Retrieve a float value as a double
    double float_value = cbor_float_get_float(&item);

    // Encode a single precision float
    float single_value;
    std::memcpy(&single_value, Data, sizeof(float));
    size_t single_encoded_length = cbor_encode_single(single_value, buffer, buffer_size);

    // Encode a double precision float
    double double_value;
    if (Size >= sizeof(double)) {
        std::memcpy(&double_value, Data, sizeof(double));
    } else {
        double_value = static_cast<double>(single_value);
    }
    size_t double_encoded_length = cbor_encode_double(double_value, buffer, buffer_size);

    // Encode a half-precision float
    size_t half_encoded_length = cbor_encode_half(single_value, buffer, buffer_size);

    // Log the results (optional, can be removed in actual fuzzing)
    std::cout << "isFloat: " << isFloat << "\n";
    std::cout << "Serialized Length: " << serialized_length << "\n";
    std::cout << "Float Value: " << float_value << "\n";
    std::cout << "Single Encoded Length: " << single_encoded_length << "\n";
    std::cout << "Double Encoded Length: " << double_encoded_length << "\n";
    std::cout << "Half Encoded Length: " << half_encoded_length << "\n";

    return 0;
}