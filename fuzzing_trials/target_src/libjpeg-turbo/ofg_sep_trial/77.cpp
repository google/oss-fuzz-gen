#include <cstdint>
#include <cstdlib>
#include <cstdio>

// Assuming the function is part of a C library, we wrap it in extern "C"
extern "C" {
    int tjPlaneWidth(int componentID, int width, int subsamp);
}

extern "C" int LLVMFuzzerTestOneInput_77(const uint8_t *data, size_t size) {
    if (size < 3) {
        // We need at least 3 bytes to extract three integers
        return 0;
    }

    // Extract three integers from the input data
    int componentID = static_cast<int>(data[0]);
    int width = static_cast<int>(data[1]);
    int subsamp = static_cast<int>(data[2]);

    // Call the function-under-test
    int result = tjPlaneWidth(componentID, width, subsamp);

    // Optional: Print the result for debugging purposes
    // printf("tjPlaneWidth(%d, %d, %d) = %d\n", componentID, width, subsamp, result);

    return 0;
}