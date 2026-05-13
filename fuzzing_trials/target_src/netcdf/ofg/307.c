#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

// Assuming nc_type is an enum or typedef defined elsewhere
typedef enum {
    NC_TYPE_INT,
    NC_TYPE_FLOAT,
    NC_TYPE_STRING
    // Add other types as necessary
} nc_type;

// Mock implementation of the nc_insert_compound_307 function
int nc_insert_compound_307(int id, nc_type type1, const char *name, size_t size, nc_type type2) {
    // Mock implementation for demonstration purposes
    // Simulate some processing based on the inputs
    if (id < 0 || name == NULL || size == 0) {
        return -1; // Indicate an error
    }
    return 0; // Indicate success
}

int LLVMFuzzerTestOneInput_307(const uint8_t *data, size_t size) {
    if (size < 4) { // Ensure there are enough bytes for id, type1, type2, and at least one byte for the name
        return 0;
    }

    int id = (int)data[0];  // Use the first byte for id
    nc_type type1 = (nc_type)(data[1] % 3); // Use the second byte for type1, assuming 3 types
    nc_type type2 = (nc_type)(data[2] % 3); // Use the third byte for type2, assuming 3 types

    // Use the remaining data to create a dynamic name
    size_t name_size = size - 3; // Remaining bytes after id, type1, and type2
    char *name = (char *)malloc(name_size + 1);
    if (name == NULL) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(name, data + 3, name_size);
    name[name_size] = '\0'; // Null-terminate the string

    // Ensure the name is not empty to increase meaningful input
    if (name_size > 0 && name[0] != '\0') {
        // Call the function-under-test
        int result = nc_insert_compound_307(id, type1, name, name_size, type2);
        // Check result to ensure the function-under-test is being exercised
        if (result == 0) {
            // Simulate some further processing if needed
        }
    } else {
        // If the name is empty, simulate a non-empty name to ensure the function is invoked
        strcpy(name, "default_name");
        int result = nc_insert_compound_307(id, type1, name, strlen(name), type2);
        if (result == 0) {
            // Simulate some further processing if needed
        }
    }

    // Free allocated memory
    free(name);

    return 0;
}