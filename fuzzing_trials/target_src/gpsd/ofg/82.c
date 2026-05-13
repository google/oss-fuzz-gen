#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assuming gps_device_t is defined somewhere
struct gps_device_t {
    // Dummy fields for illustration purposes
    int dummy_field1;
    int dummy_field2;
};

// Function signature provided
void nmea_subframe_dump(struct gps_device_t *device, char *buffer, size_t size);

int LLVMFuzzerTestOneInput_82(const uint8_t *data, size_t size) {
    // Ensure there is enough data to initialize the buffer
    if (size < 1) {
        return 0;
    }

    // Initialize gps_device_t structure
    struct gps_device_t device;
    device.dummy_field1 = 1;
    device.dummy_field2 = 2;

    // Allocate memory for the buffer, with an extra byte for null-termination
    char *buffer = (char *)malloc(size + 1);
    if (buffer == NULL) {
        return 0;
    }

    // Copy data into the buffer
    memcpy(buffer, data, size);

    // Null-terminate the buffer to make it a valid C-string
    buffer[size] = '\0';

    // Call the function-under-test with non-empty buffer
    // Ensure the buffer is not empty by checking size
    if (size > 0) {
        // Adjust the size passed to the function to consider the null-termination
        nmea_subframe_dump(&device, buffer, size);
    }

    // Free the allocated buffer
    free(buffer);

    return 0;
}