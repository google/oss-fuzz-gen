#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Define the hdr_field structure
struct hdr_field {
    char *name;
    char *value;
};

// Function under test
void clean_hdr_field(const struct hdr_field *field);

// Fuzzing harness
int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Not enough data to form a valid hdr_field
    }

    // Allocate memory for the hdr_field
    struct hdr_field field;
    size_t name_len = data[0] % size; // Ensure name_len is within bounds
    size_t value_len = size - name_len - 1; // Ensure value_len is within bounds

    // Allocate and copy data for the name
    field.name = (char *)malloc(name_len + 1);
    if (field.name == NULL) {
        return 0; // Memory allocation failed
    }
    memcpy(field.name, data + 1, name_len);
    field.name[name_len] = '\0'; // Null-terminate the string

    // Allocate and copy data for the value
    field.value = (char *)malloc(value_len + 1);
    if (field.value == NULL) {
        free(field.name);
        return 0; // Memory allocation failed
    }
    memcpy(field.value, data + 1 + name_len, value_len);
    field.value[value_len] = '\0'; // Null-terminate the string

    // Call the function under test
    clean_hdr_field(&field);

    // Free allocated memory
    free(field.name);
    free(field.value);

    return 0;
}