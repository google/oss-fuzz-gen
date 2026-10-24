extern "C" {
    #include <cbor.h>
    #include <stdint.h>
    #include <stdlib.h>
    #include <string.h>
}

extern "C" int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0; // Early exit if there's no data
    }

    // Initialize a cbor_item_t structure
    cbor_item_t *item = cbor_new_definite_bytestring();
    if (item == NULL) {
        return 0;
    }

    // Create a buffer to hold the data
    unsigned char *buffer = (unsigned char *)malloc(size);
    if (buffer == NULL) {
        cbor_decref(&item);
        return 0;
    }

    // Copy the input data to the buffer
    memcpy(buffer, data, size);

    // Set the bytestring content
    cbor_bytestring_set_handle(item, buffer, size);

    // Prepare an output buffer for serialization
    size_t buffer_size = cbor_serialized_size(item); // Get the correct serialized size
    unsigned char *output_buffer = (unsigned char *)malloc(buffer_size);
    if (output_buffer == NULL) {
        cbor_decref(&item);
        free(buffer);
        return 0;
    }

    // Serialize the CBOR item
    if (!cbor_serialize(item, output_buffer, buffer_size)) {
        // Handle serialization failure if needed
        cbor_decref(&item);
        free(output_buffer);
        return 0;
    }

    // Deserialize the serialized data back into a CBOR item
    struct cbor_load_result load_result;
    cbor_item_t *decoded_item = cbor_load(output_buffer, buffer_size, &load_result);

    if (decoded_item != NULL) {
        // Perform additional operations on the decoded item
        // For example, check the type and perform operations based on it
        if (cbor_isa_bytestring(decoded_item)) {
            size_t decoded_size;
            unsigned char *decoded_data = cbor_bytestring_handle(decoded_item);
            decoded_size = cbor_bytestring_length(decoded_item);

            // Further operations can be added here
            (void)decoded_data; // Use decoded_data as needed
            (void)decoded_size; // Use decoded_size as needed
        }

        // Clean up the decoded item
        cbor_decref(&decoded_item);
    }

    // Clean up
    cbor_decref(&item);
    free(output_buffer);

    return 0;
}