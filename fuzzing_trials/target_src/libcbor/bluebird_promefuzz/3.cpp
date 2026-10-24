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

#include "cstdint"
#include "cstdlib"
#include <cstring>

static cbor_item_t* create_random_cbor_item(const uint8_t* Data, size_t Size) {
    if (Size == 0) {
        return nullptr;
    }
    cbor_type type = static_cast<cbor_type>(Data[0] % 8);
    cbor_item_t* item = nullptr;
    switch (type) {
        case CBOR_TYPE_UINT:
            item = cbor_new_int8();
            cbor_set_uint8(item, Data[0]);
            break;
        case CBOR_TYPE_NEGINT:
            item = cbor_new_int8();
            cbor_set_uint8(item, Data[0]);
            break;
        case CBOR_TYPE_BYTESTRING:
            item = cbor_new_definite_bytestring();
            cbor_bytestring_set_handle(item, (cbor_mutable_data)malloc(Size - 1), Size - 1);
            memcpy(cbor_bytestring_handle(item), Data + 1, Size - 1);
            break;
        case CBOR_TYPE_STRING:
            item = cbor_new_definite_string();
            cbor_string_set_handle(item, (cbor_mutable_data)malloc(Size - 1), Size - 1);
            memcpy(cbor_string_handle(item), Data + 1, Size - 1);
            break;
        case CBOR_TYPE_ARRAY:
            item = cbor_new_definite_array(Size - 1);
            for (size_t i = 1; i < Size; ++i) {
                cbor_array_push(item, cbor_build_uint8(Data[i]));
            }
            break;
        case CBOR_TYPE_MAP:
            item = cbor_new_definite_map((Size - 1) / 2);
            for (size_t i = 1; i + 1 < Size; i += 2) {
                cbor_map_add(item, (struct cbor_pair){cbor_build_uint8(Data[i]), cbor_build_uint8(Data[i + 1])});
            }
            break;
        case CBOR_TYPE_TAG:
            if (Size > 1) {
                item = cbor_new_tag(Data[0]);
                cbor_tag_set_item(item, cbor_build_uint8(Data[1]));
            }
            break;
        case CBOR_TYPE_FLOAT_CTRL:
            item = cbor_new_float2();
            cbor_set_float2(item, static_cast<float>(Data[0]));
            break;
    }
    return item;
}

extern "C" int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    cbor_item_t* item = create_random_cbor_item(Data, Size);
    if (!item) {
        return 0;
    }

    size_t buffer_size = 1024;
    unsigned char buffer[1024];

    // Fuzz cbor_serialize_array
    if (cbor_isa_array(item)) {
        cbor_serialize_array(item, buffer, buffer_size);
    }

    // Fuzz cbor_serialize_bytestring
    if (cbor_isa_bytestring(item)) {
        cbor_serialize_bytestring(item, buffer, buffer_size);
    }

    // Fuzz cbor_serialize_tag
    if (cbor_isa_tag(item)) {
        cbor_serialize_tag(item, buffer, buffer_size);
    }

    // Fuzz cbor_serialize
    cbor_serialize(item, buffer, buffer_size);

    // Fuzz cbor_serialize_uint
    if (cbor_isa_uint(item)) {
        cbor_serialize_uint(item, buffer, buffer_size);
    }

    // Fuzz cbor_serialize_string
    if (cbor_isa_string(item)) {
        cbor_serialize_string(item, buffer, buffer_size);
    }


        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from cbor_serialize_tag to cbor_encode_half

        size_t ret_cbor_encode_half_qsrrk = cbor_encode_half(0, buffer, Size);
        if (ret_cbor_encode_half_qsrrk < 0){
        	return 0;
        }

        // End mutation: Producer.APPEND_MUTATOR

    cbor_decref(&item);
    return 0;
}