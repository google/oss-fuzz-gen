#include <cbor.h>
#include <stdint.h>
#include <stddef.h>

extern "C" {
    bool cbor_array_replace(cbor_item_t *, size_t, cbor_item_t *);
}

extern "C" int LLVMFuzzerTestOneInput_102(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Ensure there's enough data to work with
    }

    // Create a CBOR array item
    cbor_item_t *array = cbor_new_definite_array(1);

    // Create a CBOR item to replace in the array
    cbor_item_t *replacement = cbor_new_int8();

    // Use the first byte of data to decide the position
    size_t position = data[0] % 1; // Only one item in the array

    // Use the second byte of data to set the value of the replacement item
    cbor_set_uint8(replacement, data[1]);

    // Call the function under test
    cbor_array_replace(array, position, replacement);

    // Clean up
    cbor_decref(&array);
    cbor_decref(&replacement);

    return 0;
}