#include <stdint.h>
#include <stddef.h>
#include <stdio.h>  // Include for printf function

// Include the necessary GPSD headers and define GPSD_CONFIG_H to avoid errors
#define GPSD_CONFIG_H
#define MAX_DEVICES 4  // Define MAX_DEVICES to resolve the undeclared identifier error
#include "/src/gpsd/gpsd-3.27.6~dev/include/gpsd_config.h"
#include "/src/gpsd/gpsd-3.27.6~dev/include/gpsd.h"
#include "/src/gpsd/gpsd-3.27.6~dev/include/compiler.h"

// Declare the netlib_errstr function prototype if not included in gpsd.h
const char *netlib_errstr(int error_code);

int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
    // Initialize an integer from the input data
    int input_value = 0;

    // Ensure there is enough data to read an integer
    if (size >= sizeof(int)) {
        // Copy the data into the integer
        input_value = *(const int *)data;
    }

    // Call the function-under-test
    const char *error_string = netlib_errstr(input_value);

    // Use the returned error string in some way to avoid compiler optimizations
    if (error_string != NULL) {
        // Print the error string to ensure the function is used
        printf("Error string: %s\n", error_string);
    }

    return 0;
}