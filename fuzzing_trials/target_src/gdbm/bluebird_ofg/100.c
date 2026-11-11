#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

// Function-under-test
int variable_set(const char *name, int value_type, void *value);

int LLVMFuzzerTestOneInput_100(const uint8_t *data, size_t size) {
    // Ensure we have enough data to work with
    if (size < sizeof(int) + 1) {
        return 0;
    }

    // Extract a string for the name parameter
    size_t name_len = size - sizeof(int);
    char name[name_len + 1];
    memcpy(name, data, name_len);
    name[name_len] = '\0'; // Null-terminate the string

    // Extract an integer for the value_type parameter
    int value_type;
    memcpy(&value_type, data + name_len, sizeof(int));

    // Use the rest of the data for the value parameter
    void *value = (void *)(data + name_len + sizeof(int));

    // Call the function-under-test
    variable_set(name, value_type, value);

    return 0;
}