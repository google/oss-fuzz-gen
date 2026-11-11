extern "C" {
    #include <cbor.h>
}

extern "C" int LLVMFuzzerTestOneInput_159(const uint8_t *data, size_t size) {
    // Ensure the buffer is not NULL and has a valid size
    if (size == 0) {
        return 0;
    }

    // Allocate a buffer for encoding
    unsigned char *buffer = new unsigned char[size];

    // Call the function-under-test
    size_t encoded_size = cbor_encode_null(buffer, size);

    // Use the encoded_size in some way to avoid unused variable warning
    (void)encoded_size;

    // Clean up
    delete[] buffer;

    return 0;
}