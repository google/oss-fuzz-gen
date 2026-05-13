#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>  // Include for size_t and ptrdiff_t

extern int nc_put_vars_text(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const char *data);

int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Define and initialize the parameters for nc_put_vars_text
    int ncid = 1; // Example non-zero value
    int varid = 1; // Example non-zero value

    // Ensure size is large enough to extract necessary parameters
    if (size < 3 * sizeof(size_t) + sizeof(ptrdiff_t) + 1) {
        return 0;
    }

    // Extract size_t values from data for start and count
    size_t start[1];
    size_t count[1];
    memcpy(start, data, sizeof(size_t));
    memcpy(count, data + sizeof(size_t), sizeof(size_t));

    // Ensure count is not zero to prevent no-operation
    if (*count == 0) {
        *count = 1; // Set to minimum valid count
    }

    // Extract ptrdiff_t value for stride
    ptrdiff_t stride[1];
    memcpy(stride, data + 2 * sizeof(size_t), sizeof(ptrdiff_t));

    // Ensure stride is not zero to prevent infinite loop or no-operation
    if (*stride == 0) {
        *stride = 1; // Set to minimum valid stride
    }

    // Use the remaining data as the text input
    const char *text_data = (const char *)(data + 2 * sizeof(size_t) + sizeof(ptrdiff_t));

    // Ensure text_data is null-terminated
    char text_buffer[256]; // Example buffer size
    size_t text_length = size - (2 * sizeof(size_t) + sizeof(ptrdiff_t));
    if (text_length >= sizeof(text_buffer)) {
        text_length = sizeof(text_buffer) - 1;
    }
    memcpy(text_buffer, text_data, text_length);
    text_buffer[text_length] = '\0';

    // Call the function-under-test
    nc_put_vars_text(ncid, varid, start, count, stride, text_buffer);

    return 0;
}