#include <cstddef>
#include <cstdint>
#include <cstring>

extern "C" {
    #include "cbor.h" // Assuming cbor.h contains the declaration for cbor_encode_single
}

extern "C" int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for a float and at least one byte for the output buffer
    if (size < sizeof(float) + 1) {
        return 0;
    }

    // Extract a float value from the input data
    float floatValue;
    memcpy(&floatValue, data, sizeof(float));

    // Prepare an output buffer, taking the rest of the data as the buffer size
    unsigned char outputBuffer[256]; // Arbitrary size for the output buffer
    size_t bufferSize = size - sizeof(float);
    if (bufferSize > sizeof(outputBuffer)) {
        bufferSize = sizeof(outputBuffer);
    }

    // Call the function-under-test
    size_t result = cbor_encode_single(floatValue, outputBuffer, bufferSize);

    // Use the result to avoid compiler optimizations that remove the call
    (void)result;

    return 0;
}