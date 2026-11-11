#include <cstdint>

// Wrap the libcbor includes and functions with extern "C"
extern "C" {
    #include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_109(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for creating a cbor_item_t
    if (size < sizeof(uint16_t)) {
        return 0;
    }

    // Initialize a CBOR item
    cbor_item_t *cbor_item = cbor_new_int8(); // Use a valid function to create a CBOR item

    // Copy data into the CBOR item, ensuring it is not NULL
    if (cbor_item != NULL) {
        uint16_t value = 0;
        if (size >= sizeof(uint16_t)) {
            value = (data[0] << 8) | data[1]; // Construct a uint16_t from the input data
        }
        cbor_set_uint8(cbor_item, value & 0xFF); // Use a valid function to set the value

        // Call the function-under-test
        uint8_t result = cbor_get_uint8(cbor_item); // Use a valid function to get the value

        // Use the result to avoid compiler optimizations removing the call
        (void)result;

        // Clean up
        cbor_decref(&cbor_item);
    }

    return 0;
}