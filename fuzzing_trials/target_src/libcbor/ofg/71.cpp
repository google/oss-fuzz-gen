#include <cstdint>
#include <cbor.h>
#include <cstdlib>

extern "C" {
    // Function-under-test
    size_t cbor_array_allocated(const cbor_item_t *);
}

extern "C" int LLVMFuzzerTestOneInput_71(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to create a cbor_item_t
    if (size < sizeof(cbor_item_t)) {
        return 0;
    }

    // Allocate memory for a cbor_item_t and initialize it with fuzz data
    cbor_item_t *item = cbor_new_definite_array((size_t)data[0] % 10 + 1); // Create an array with a small number of elements
    if (item == NULL) {
        return 0;
    }

    // Call the function-under-test
    size_t allocated = cbor_array_allocated(item);

    // Clean up
    cbor_decref(&item);

    return 0;
}