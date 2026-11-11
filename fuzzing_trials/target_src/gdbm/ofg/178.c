#include <stdint.h>
#include <stddef.h>  // Include this header to define size_t

extern int escape(int);

int LLVMFuzzerTestOneInput_178(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0; // Not enough data to form an int
    }

    // Interpret the first 4 bytes of data as an int
    int input_value = *(const int *)data;

    // Call the function-under-test
    escape(input_value);

    return 0;
}