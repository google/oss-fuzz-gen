#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h> // Include for malloc and free
#include "gpsd_config.h" // Include the GPSD configuration header
#include "gpsd.h" // Assuming this header contains the definition for struct gps_device_t

// Remove the C++ linkage specification since this is C code
int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
    struct gps_device_t device;
    memset(&device, 0, sizeof(device)); // Initialize the gps_device_t structure

    // Ensure we have at least one byte to avoid passing a NULL pointer
    if (size == 0) {
        return 0;
    }

    // Create a buffer to hold the data to be written
    char *buffer = (char *)malloc(size);
    if (buffer == NULL) {
        return 0; // If memory allocation fails, exit gracefully
    }

    // Copy the data to the buffer
    memcpy(buffer, data, size);

    // Call the function-under-test
    // Use the result to avoid the unused variable warning
    ssize_t result = gpsd_serial_write(&device, buffer, size);
    (void)result; // Explicitly cast to void to suppress unused variable warning

    // Free the allocated buffer
    free(buffer);

    return 0;
}