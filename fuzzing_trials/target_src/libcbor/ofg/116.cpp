#include <cstdint>
#include <cbor.h>

extern "C" int LLVMFuzzerTestOneInput_116(const uint8_t *data, size_t size) {
    cbor_item_t *item = cbor_new_definite_bytestring();

    // Ensure the cbor_item_t is not NULL
    if (item == NULL) {
        return 0;
    }

    // Initialize the cbor_item_t with some data
    cbor_bytestring_set_handle(item, (unsigned char *)data, size);

    // Call the function-under-test
    cbor_item_t *increased_ref_item = cbor_incref(item);

    // Clean up
    // Correct the order of decref calls to avoid double-free
    if (increased_ref_item != NULL && increased_ref_item != item) {
        cbor_decref(&increased_ref_item); // Decrement the increased ref item first
    }

    cbor_decref(&item);  // Decrement the original item after

    return 0;
}