#include <cstdint>
#include <vector>
#include <cstdlib> // For free()

extern "C" {
    #include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_149(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create a cbor_item_t
    if (size < 1) {
        return 0;
    }

    // Initialize a cbor_item_t with a size based on the input data
    size_t array_size = data[0] % 10 + 1; // Limit the size to prevent excessive memory usage
    cbor_item_t *item = cbor_new_definite_array(array_size);

    // Use the provided data to simulate a CBOR array item
    for (size_t i = 0; i < array_size && i < size; ++i) {
        cbor_item_t *dummy_item = cbor_build_uint8(data[i]);
        cbor_array_push(item, dummy_item);
        cbor_decref(&dummy_item); // Decrease reference to prevent memory leaks
    }

    // Encode the CBOR item to a buffer
    unsigned char *buffer;
    size_t buffer_size;
    cbor_serialize_alloc(item, &buffer, &buffer_size);

    // Decode the buffer back to a CBOR item
    struct cbor_load_result result;
    cbor_item_t *decoded_item = cbor_load(buffer, buffer_size, &result);

    // Check if decoding was successful
    if (result.error.code != CBOR_ERR_NONE) {
        // Clean up
        cbor_decref(&item);
        free(buffer);
        return 0;
    }

    // Call the function-under-test
    if (cbor_isa_array(decoded_item)) {
        // Iterate over array elements if it is an array
        size_t array_length = cbor_array_size(decoded_item);
        for (size_t i = 0; i < array_length; ++i) {
            cbor_item_t *element = cbor_array_get(decoded_item, i);
            // Perform some operation on the element to increase coverage
            (void)cbor_isa_uint(element); // Example operation
        }
    } else if (cbor_isa_map(decoded_item)) {
        // Handle map type if needed
        size_t map_size = cbor_map_size(decoded_item);
        for (size_t i = 0; i < map_size; ++i) {
            struct cbor_pair pair = cbor_map_handle(decoded_item)[i];
            // Perform operations on map keys and values
            (void)cbor_isa_uint(pair.key); // Example operation
            (void)cbor_isa_uint(pair.value); // Example operation
        }
    }

    // Clean up
    cbor_decref(&item);
    cbor_decref(&decoded_item);
    free(buffer);

    return 0;
}