#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// Dummy implementation of variable_set_124 for demonstration purposes
int variable_set_124(const char *name, int type, void *value) {
    // Simulate some processing
    return 0;
}

int LLVMFuzzerTestOneInput_124(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract meaningful data
    if (size < sizeof(int) + 2) { // Adjusted to ensure there's enough data for name and type
        return 0;
    }

    // Extract a non-null name from the data
    // Ensure the name is null-terminated
    size_t name_length = strnlen((const char *)data, size - sizeof(int) - 1);
    if (name_length == size - sizeof(int) - 1) {
        return 0; // No null-terminator found within bounds
    }
    const char *name = (const char *)data;

    // Extract an integer type from the data
    int type = *((int *)(data + name_length + 1));

    // Extract a non-null value from the data
    void *value = (void *)(data + name_length + 1 + sizeof(int));

    // Call the function-under-test
    variable_set_124(name, type, value);

    return 0;
}