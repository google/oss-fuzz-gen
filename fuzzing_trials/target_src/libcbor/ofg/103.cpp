#include <cbor.h>
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput_103(const uint8_t *data, size_t size) {
    // Initialize CBOR context
    struct cbor_load_result load_result;
    cbor_item_t *array_item = cbor_load(data, size, &load_result);

    // Check if the loaded item is a valid CBOR array
    if (array_item == NULL || !cbor_isa_array(array_item)) {
        if (array_item != NULL) {
            cbor_decref(&array_item);
        }
        return 0;
    }

    // Create a new CBOR item to replace an element in the array
    cbor_item_t *new_item = cbor_new_int8();
    cbor_mark_negint(new_item); // Mark it as a negative integer for variety

    // Define an index to replace, ensure it's within the bounds of the array
    size_t index = cbor_array_size(array_item) > 0 ? cbor_array_size(array_item) - 1 : 0;

    // Call the function-under-test
    cbor_array_replace(array_item, index, new_item);

    // Clean up
    cbor_decref(&array_item);
    cbor_decref(&new_item);

    return 0;
}