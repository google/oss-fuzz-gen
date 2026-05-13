#include <cstdint>
#include <cstdlib>

extern "C" {
    #include <cbor.h> // Make sure to include the CBOR library header
}

extern "C" int LLVMFuzzerTestOneInput_74(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to create meaningful CBOR data
    if (size < 2) {
        return 0;
    }

    // Create a CBOR array to hold multiple items
    cbor_item_t *array_item = cbor_new_definite_array(size);

    // Ensure the array item is not NULL
    if (array_item == NULL) {
        return 0;
    }

    // Populate the array with integer items based on the input data
    for (size_t i = 0; i < size; ++i) {
        cbor_item_t *int_item = cbor_new_int8();
        if (int_item == NULL) {
            cbor_decref(&array_item);
            return 0;
        }
        cbor_set_uint8(int_item, data[i]);
        cbor_array_push(array_item, int_item);
        cbor_decref(&int_item); // Decrement reference after pushing to array
    }

    // Create a CBOR map to add more complexity
    cbor_item_t *map_item = cbor_new_definite_map(1);
    if (map_item == NULL) {
        cbor_decref(&array_item);
        return 0;
    }

    // Add the array to the map with a key
    cbor_item_t *key_item = cbor_build_uint8(0); // Key is a simple integer
    cbor_map_add(map_item, (struct cbor_pair) {
        .key = cbor_move(key_item),
        .value = cbor_move(array_item)
    });

    // Call the function-under-test with the map
    // Assuming the function under test is cbor_serialize or similar
    unsigned char *buffer;
    size_t buffer_size;
    cbor_serialize_alloc(map_item, &buffer, &buffer_size);

    // Clean up
    cbor_decref(&map_item);
    free(buffer);

    return 0;
}