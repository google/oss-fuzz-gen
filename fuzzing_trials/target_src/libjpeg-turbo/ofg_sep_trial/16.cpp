#include <cstdint>
#include <cstdlib>

extern "C" {
    // Assuming the function is declared in a header file related to the library
    int tj3YUVPlaneWidth(int componentID, int width, int subsampling);
}

extern "C" int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract three integers
    if (size < 3 * sizeof(int)) {
        return 0;
    }

    // Extract three integers from the input data
    int componentID = static_cast<int>(data[0]); // Using first byte for componentID
    int width = static_cast<int>(data[1]);       // Using second byte for width
    int subsampling = static_cast<int>(data[2]); // Using third byte for subsampling

    // Call the function under test
    int result = tj3YUVPlaneWidth(componentID, width, subsampling);

    // Return 0 to indicate successful execution
    return 0;
}