extern "C" {
    #include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_97(const uint8_t *data, size_t size) {
    // Create memory context for CBOR items
    struct cbor_load_result result;
    cbor_item_t *map_item = cbor_load(data, size, &result);
    cbor_item_t *value_item = cbor_load(data, size, &result);

    // Ensure both items are not NULL and are of the correct type
    if (map_item == NULL || value_item == NULL) {
        if (map_item != NULL) cbor_decref(&map_item);
        if (value_item != NULL) cbor_decref(&value_item);
        return 0;
    }

    // Ensure the map_item is actually a map
    if (!cbor_isa_map(map_item)) {
        cbor_decref(&map_item);
        cbor_decref(&value_item);
        return 0;
    }

    // Call the function-under-test
    _cbor_map_add_value(map_item, value_item);

    // Clean up
    cbor_decref(&map_item);
    cbor_decref(&value_item);

    return 0;
}