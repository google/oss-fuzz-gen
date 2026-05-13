extern "C" {
    #include <stdint.h>
    #include <string.h>
    #include "cbor.h"
}

extern "C" int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Use the input data to create a CBOR item
    struct cbor_load_result load_result;
    cbor_item_t *item = cbor_load(data, size, &load_result);

    if (item != NULL) {
        // Perform operations based on the type of the item
        cbor_type type = cbor_typeof(item);
        switch (type) {
            case CBOR_TYPE_UINT:
            case CBOR_TYPE_NEGINT:
            case CBOR_TYPE_BYTESTRING:
            case CBOR_TYPE_STRING:
            case CBOR_TYPE_ARRAY:
            case CBOR_TYPE_MAP:
            case CBOR_TYPE_TAG:
            case CBOR_TYPE_FLOAT_CTRL: {
                // Serialize and deserialize to ensure validity
                unsigned char buffer[512];
                size_t serialized_size = cbor_serialize(item, buffer, sizeof(buffer));
                if (serialized_size > 0) {
                    struct cbor_load_result result;
                    cbor_item_t *deserialized_item = cbor_load(buffer, serialized_size, &result);
                    if (deserialized_item != NULL) {
                        cbor_decref(&deserialized_item);
                    }
                }
                break;
            }
            default:
                break;
        }

        // Clean up
        cbor_decref(&item);
    }

    return 0;
}