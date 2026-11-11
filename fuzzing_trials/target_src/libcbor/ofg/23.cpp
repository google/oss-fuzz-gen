extern "C" {
    #include <stdint.h>
    #include <stddef.h>
    #include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_23(const uint8_t *data, size_t size) {
    // Ensure there is enough data for meaningful input
    if (size < 1) {
        return 0;
    }

    // Initialize a CBOR integer item
    cbor_item_t *int_item = cbor_new_int8();
    if (int_item == NULL) {
        return 0;
    }

    // Set the value of the integer item using the first byte of data
    cbor_set_uint8(int_item, data[0]);

    // Allocate a buffer to serialize the integer
    unsigned char buffer[32]; // Adjust the size as needed

    // Call the function-under-test using the correct serialization function
    size_t serialized_size = cbor_serialize_uint(int_item, buffer, sizeof(buffer));

    // Clean up
    cbor_decref(&int_item);

    return 0;
}