#include <cstdint>
#include <cstring> // Include for memcpy

extern "C" {
    #include <cbor.h> // Include the necessary C header for libcbor
}

extern "C" int LLVMFuzzerTestOneInput_121(const uint8_t *data, size_t size) {
    // Declare and initialize a float variable
    float input_value = 0.0f;

    // Ensure there is enough data to interpret as a float
    if (size >= sizeof(float)) {
        // Use memcpy to safely copy the data into the float variable
        std::memcpy(&input_value, data, sizeof(float));
    } else {
        // If not enough data for a float, pad with zeros to ensure valid float
        uint8_t padded_data[sizeof(float)] = {0};
        std::memcpy(padded_data, data, size);
        std::memcpy(&input_value, padded_data, sizeof(float));
    }

    // Call the function-under-test with the float value
    cbor_item_t *item = cbor_build_float4(input_value);

    // Check if the item is successfully created
    if (item != NULL) {
        // Perform operations on the item to ensure code coverage
        // For example, serialize the item to a buffer
        unsigned char *buffer = NULL;
        size_t buffer_size = 0;
        cbor_serialize_alloc(item, &buffer, &buffer_size);

        // Free the buffer if it was allocated
        if (buffer != NULL) {
            free(buffer);
        }

        // Clean up the item
        cbor_decref(&item);
    }

    return 0;
}