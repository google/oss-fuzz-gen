extern "C" {
    #include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_141(const uint8_t *data, size_t size) {
    if (size < sizeof(uint16_t)) {
        return 0; // Ensure there's enough data to construct a uint16_t
    }

    // Construct a uint16_t from the input data
    uint16_t value = *(reinterpret_cast<const uint16_t*>(data));

    // Call the function-under-test
    cbor_item_t *item = cbor_build_negint16(value);

    // Clean up the cbor_item_t object if it was created
    if (item != NULL) {
        cbor_decref(&item);
    }

    return 0;
}