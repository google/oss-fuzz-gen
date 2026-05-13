#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assuming the definition of struct datadef and struct dsegm are available
struct datadef {
    int some_field; // Example field, replace with actual fields
};

struct dsegm {
    int another_field; // Example field, replace with actual fields
};

// Function prototype
struct dsegm * dsegm_new_field(struct datadef *, char *, int);

int LLVMFuzzerTestOneInput_96(const uint8_t *data, size_t size) {
    // Initialize variables
    struct datadef datadef_instance;
    char field_name[256]; // Assuming a maximum length for the field name
    int field_value;

    // Ensure data is large enough to fill the required fields
    if (size < sizeof(datadef_instance) + sizeof(field_name) + sizeof(field_value)) {
        return 0;
    }

    // Fill the datadef_instance with data
    memcpy(&datadef_instance, data, sizeof(datadef_instance));

    // Fill the field_name with data
    memcpy(field_name, data + sizeof(datadef_instance), sizeof(field_name) - 1);
    field_name[sizeof(field_name) - 1] = '\0'; // Ensure null-termination

    // Fill the field_value with data
    memcpy(&field_value, data + sizeof(datadef_instance) + sizeof(field_name), sizeof(field_value));

    // Call the function-under-test
    struct dsegm *result = dsegm_new_field(&datadef_instance, field_name, field_value);

    // Free the result if necessary
    // Assuming dsegm_new_field allocates memory, free it if needed
    free(result);

    return 0;
}