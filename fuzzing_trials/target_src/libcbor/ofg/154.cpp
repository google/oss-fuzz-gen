extern "C" {
    #include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_154(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to create a cbor_item_t object
    if (size < 1) return 0;

    // Create a cbor_item_t object
    cbor_item_t *item = cbor_new_definite_array(size);

    // Populate the cbor_item_t with data
    for (size_t i = 0; i < size; ++i) {
        cbor_item_t *element = cbor_build_uint8(data[i]);
        cbor_array_push(item, element);
    }

    // Call the function-under-test
    size_t refcount = cbor_refcount(item);

    // Clean up
    cbor_decref(&item);

    return 0;
}