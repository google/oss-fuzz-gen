#include <cbor.h>
#include <cstdint>
#include <cstdlib>

extern "C" {
    size_t cbor_array_allocated(const cbor_item_t *);
}

extern "C" int LLVMFuzzerTestOneInput_72(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Use the first byte of data to determine the size of the CBOR array
    size_t array_size = data[0] % 10 + 1; // Limit the size to prevent excessive memory usage
    cbor_item_t *item = cbor_new_definite_array(array_size);

    // Populate the CBOR array with uint8 items from the data
    for (size_t i = 0; i < array_size && i < size; ++i) {
        cbor_item_t *element = cbor_build_uint8(data[i]);
        cbor_array_push(item, element);
        cbor_decref(&element); // Decrement reference count after pushing
    }

    // Call the function-under-test
    size_t allocated = cbor_array_allocated(item);

    // Check the result of the function-under-test
    if (allocated != array_size) {
        // If the allocated size is not as expected, log an error or handle it
        abort();
    }

    // Clean up
    cbor_decref(&item);

    return 0;
}