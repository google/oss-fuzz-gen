extern "C" {
    #include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_165(const uint8_t *data, size_t size) {
    // Parse the input data as a CBOR item
    struct cbor_load_result result;
    cbor_item_t *item = cbor_load(data, size, &result);

    // Check if the item was successfully created
    if (item != NULL) {
        // Perform operations on the item if needed
        // For example, checking the type of the item
        if (cbor_isa_string(item)) {
            // Do something with the string item
        }

        // Clean up the allocated cbor item
        cbor_decref(&item);
    }

    return 0;
}