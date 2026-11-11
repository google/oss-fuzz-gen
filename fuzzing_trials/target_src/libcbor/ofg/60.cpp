extern "C" {
    #include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    // Initialize the cbor_load_result structure
    struct cbor_load_result load_result;

    // Call the function-under-test with the provided data and size
    cbor_item_t *item = cbor_load(data, size, &load_result);

    // If item is not NULL, free the allocated cbor_item_t
    if (item != NULL) {
        cbor_decref(&item);
    }

    return 0;
}