#include <cstddef>
#include <cstdint>
#include <cassert>
#include <cstring>
#include <cstdlib>

extern "C" {
    #include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a cbor_item_t
    if (size < 1) {
        return 0;
    }

    // Initialize a cbor_item_t based on the first byte of data
    cbor_item_t *item = nullptr;
    uint8_t* data_copy = nullptr;

    switch (data[0] % 3) {
        case 0:
            item = cbor_new_int8();
            assert(item != NULL);
            cbor_set_uint8(item, data[0]);
            break;
        case 1:
            item = cbor_new_definite_bytestring();
            assert(item != NULL);
            // Ensure that the data passed to cbor_bytestring_set_handle is not freed prematurely
            data_copy = (uint8_t*)malloc(size);
            assert(data_copy != NULL);
            memcpy(data_copy, data, size);
            cbor_bytestring_set_handle(item, data_copy, size);
            break;
        case 2:
            item = cbor_new_definite_array(size);
            assert(item != NULL);
            for (size_t i = 0; i < size; i++) {
                // Capture the return value to avoid warning
                bool result = cbor_array_push(item, cbor_build_uint8(data[i]));
                assert(result);
            }
            break;
        default:
            break;
    }

    if (item != nullptr) {
        // Call various functions to test the item
        bool is_uint = cbor_isa_uint(item);
        bool is_bytestring = cbor_isa_bytestring(item);
        bool is_array = cbor_isa_array(item);

        // Additional operations to maximize code coverage
        if (is_uint) {
            uint8_t value = cbor_get_uint8(item);
            cbor_set_uint8(item, value + 1);
        } else if (is_bytestring) {
            size_t length = cbor_bytestring_length(item);
            assert(length == size);
        } else if (is_array) {
            size_t array_size = cbor_array_size(item);
            assert(array_size == size);
        }

        // Use cbor_copy to test copying functionality
        cbor_item_t *copy = cbor_copy(item);
        assert(copy != NULL);
        cbor_decref(&copy);

        // Clean up
        cbor_decref(&item);
    }

    return 0;
}