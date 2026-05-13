#include <cstdint>
#include <cstdlib>

extern "C" {
    // Include the necessary header for tj3YUVPlaneHeight if available
    // #include "turbojpeg.h" // Example: Uncomment and adjust if the header is available

    // Declare the function signature if not included from a header
    int tj3YUVPlaneHeight(int componentID, int width, int align);
}

extern "C" int LLVMFuzzerTestOneInput_150(const uint8_t *data, size_t size) {
    // Initialize variables for the function parameters
    int componentID = 0; // Example value, can be varied as needed
    int width = 1;       // Example value, must be > 0
    int align = 1;       // Example value, must be > 0

    // Ensure that the input data is large enough to extract meaningful values
    if (size >= 3) {
        // Extract values from the input data to use as parameters
        componentID = data[0] % 3; // Assuming 3 components (e.g., Y, U, V)
        width = data[1] + 1;       // Ensure width is > 0
        align = data[2] + 1;       // Ensure align is > 0
    }

    // Call the function-under-test with the initialized parameters
    int result = tj3YUVPlaneHeight(componentID, width, align);

    // Use the result in some way to prevent compiler optimizations from removing the call
    volatile int prevent_optimization = result;
    (void)prevent_optimization;

    return 0;
}