#include <cstdint>
#include <cbor.h>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    // If the input size is zero, return early
    if (size == 0) {
        return 0;
    }

    // Attempt to parse the input data as a CBOR item
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // Check if the item was successfully parsed
    if (item != NULL) {
        // Perform operations on the item to increase coverage
        cbor_type type = cbor_typeof(item);

        switch (type) {
            case CBOR_TYPE_UINT:
                // Handle unsigned integer type
                cbor_int_get_width(item);
                break;
            case CBOR_TYPE_NEGINT:
                // Handle negative integer type
                cbor_int_get_width(item);
                break;
            case CBOR_TYPE_BYTESTRING:
                // Handle byte string type
                cbor_bytestring_handle(item);
                break;
            case CBOR_TYPE_STRING:
                // Handle string type
                cbor_string_handle(item);
                break;
            case CBOR_TYPE_ARRAY:
                // Handle array type
                cbor_array_size(item);
                break;
            case CBOR_TYPE_MAP:
                // Handle map type
                cbor_map_size(item);
                break;
            case CBOR_TYPE_TAG:
                // Handle tag type
                cbor_tag_value(item);
                break;
            case CBOR_TYPE_FLOAT_CTRL:
                // Handle float/control type
                cbor_float_get_width(item);
                break;
            default:
                break;
        }

        // Clean up
        cbor_decref(&item);
    }

    return 0;
}