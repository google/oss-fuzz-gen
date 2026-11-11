#include <stdint.h>
#include <string.h> // Include string.h for memcpy

int escape(int);

int LLVMFuzzerTestOneInput_177(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0; // Ensure there is enough data to form an int
    }

    int input_value;
    // Copy the first sizeof(int) bytes from data into input_value
    // This ensures we have a valid int to pass to the escape function
    memcpy(&input_value, data, sizeof(int));

    // Call the function-under-test with the fuzzed integer
    escape(input_value);

    return 0;
}