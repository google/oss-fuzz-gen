#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

extern ssize_t hex_escapes(char *, const char *);

int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create two strings
    if (size < 2) {
        return 0;
    }

    // Allocate memory for the destination and source strings
    char dest[256];
    char src[256];

    // Limit the size of the strings to avoid overflow
    size_t dest_size = size / 2 < sizeof(dest) - 1 ? size / 2 : sizeof(dest) - 1;
    size_t src_size = size - dest_size < sizeof(src) - 1 ? size - dest_size : sizeof(src) - 1;

    // Copy data into the source and destination strings
    memcpy(dest, data, dest_size);
    dest[dest_size] = '\0'; // Null-terminate the destination string

    memcpy(src, data + dest_size, src_size);
    src[src_size] = '\0'; // Null-terminate the source string

    // Call the function-under-test
    hex_escapes(dest, src);

    return 0;
}