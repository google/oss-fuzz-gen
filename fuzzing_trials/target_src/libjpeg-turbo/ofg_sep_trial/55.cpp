#include <cstdint>
#include <cstdlib>
#include <cstdio>

// Assume the function is defined elsewhere
extern "C" {
    int tjPlaneHeight(int componentID, int width, int subsampling);
}

extern "C" int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract three integers
    if (size < 3 * sizeof(int)) {
        return 0;
    }

    // Extract integers from the input data
    int componentID = static_cast<int>(data[0]); // Use the first byte for componentID
    int width = static_cast<int>(data[1]);       // Use the second byte for width
    int subsampling = static_cast<int>(data[2]); // Use the third byte for subsampling

    // Call the function-under-test
    int result = tjPlaneHeight(componentID, width, subsampling);

    // Optionally print the result for debugging
    printf("tjPlaneHeight(%d, %d, %d) = %d\n", componentID, width, subsampling, result);

    return 0;
}