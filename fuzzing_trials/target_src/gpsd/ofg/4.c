#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Assuming the definition of struct gps_device_t is available
struct gps_device_t {
    // Example fields, actual definition may vary
    int some_field;
    double another_field;
};

// Forward declaration of the function-under-test
void nmea_tpv_dump(struct gps_device_t *device, char *buf, size_t len);

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Initialize the gps_device_t structure
    struct gps_device_t device;
    device.some_field = 1; // Example initialization
    device.another_field = 1.0; // Example initialization

    // Allocate a buffer for the string
    char buf[256]; // Example buffer size
    size_t buf_size = sizeof(buf);

    // Ensure the buffer is not empty
    if (size > 0) {
        // Copy data into the buffer, ensuring it is null-terminated
        size_t copy_size = size < buf_size - 1 ? size : buf_size - 1;
        memcpy(buf, data, copy_size);
        buf[copy_size] = '\0';
    } else {
        buf[0] = '\0'; // Ensure the buffer is null-terminated
    }

    // Call the function-under-test
    nmea_tpv_dump(&device, buf, buf_size);

    return 0;
}