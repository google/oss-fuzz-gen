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
#include "/src/libcbor/src/cbor/serialization.h"
#include "cbor.h"
}

#include <cstddef>
#include "cstdint"
#include "cstdlib"
#include <cstring>

static cbor_item_t* create_cbor_item(cbor_type type, const uint8_t* data, size_t size) {
    cbor_item_t* item = nullptr;
    if (type == CBOR_TYPE_UINT) {
        if (size >= sizeof(uint64_t)) {
            item = cbor_build_uint64(*reinterpret_cast<const uint64_t*>(data));
        }
    } else if (type == CBOR_TYPE_BYTESTRING) {
        item = cbor_build_bytestring(data, size);
    } else if (type == CBOR_TYPE_STRING) {
        // Ensure null-termination for string
        std::string str(reinterpret_cast<const char*>(data), size);
        item = cbor_build_string(str.c_str());
    } else if (type == CBOR_TYPE_ARRAY) {
        item = cbor_new_definite_array(size);
        for (size_t i = 0; i < size; ++i) {
            cbor_array_push(item, cbor_build_uint8(data[i]));
        }
    } else if (type == CBOR_TYPE_TAG) {
        if (size >= sizeof(uint64_t)) {
            item = cbor_new_tag(*reinterpret_cast<const uint64_t*>(data));
            if (item) {
                cbor_item_t* tagged_item = cbor_build_uint8(0); // Dummy tagged item
                cbor_tag_set_item(item, tagged_item);
            }
        }
    }
    return item;
}

extern "C" int LLVMFuzzerTestOneInput_21(const uint8_t* Data, size_t Size) {
    if (Size < 1) return 0;

    uint8_t buffer[1024];
    size_t buffer_size = sizeof(buffer);

    cbor_type type = static_cast<cbor_type>(Data[0] % 7);  // Choose a type based on first byte
    cbor_item_t* item = create_cbor_item(type, Data + 1, Size - 1);

    if (item) {
        switch (type) {
            case CBOR_TYPE_UINT:
                cbor_serialize_uint(item, buffer, buffer_size);
                break;
            case CBOR_TYPE_BYTESTRING:
                cbor_serialize_bytestring(item, buffer, buffer_size);
                break;
            case CBOR_TYPE_STRING:
                cbor_serialize_string(item, buffer, buffer_size);
                break;
            case CBOR_TYPE_ARRAY:
                cbor_serialize_array(item, buffer, buffer_size);
                break;
            case CBOR_TYPE_TAG:
                cbor_serialize_tag(item, buffer, buffer_size);
                break;
            default:
                cbor_serialize(item, buffer, buffer_size);
                break;
        }
        cbor_decref(&item);
    }

    return 0;
}