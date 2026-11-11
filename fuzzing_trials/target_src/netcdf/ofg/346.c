#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Assuming NC_Dispatch is a struct defined elsewhere
typedef struct {
    // Placeholder for actual members of NC_Dispatch
    int dummy;
} NC_Dispatch;

// Stub for the function-under-test
int nc_def_user_format_346(int param1, NC_Dispatch *dispatch, char *name) {
    // Placeholder implementation
    // Simulating some behavior based on the inputs
    if (param1 == 0 || dispatch == NULL || name == NULL || strlen(name) == 0) {
        return -1; // Simulate an error condition
    }
    return 0; // Simulate success
}

int LLVMFuzzerTestOneInput_346(const uint8_t *data, size_t size) {
    if (size < sizeof(int) + sizeof(NC_Dispatch) + 1) {
        return 0; // Not enough data to proceed
    }

    // Extract an integer from the data
    int param1 = *(int *)data;

    // Extract a NC_Dispatch structure from the data
    NC_Dispatch dispatch;
    memcpy(&dispatch, data + sizeof(int), sizeof(NC_Dispatch));

    // Extract a null-terminated string from the remaining data
    size_t name_size = size - sizeof(int) - sizeof(NC_Dispatch);
    char *name = (char *)malloc(name_size + 1);
    if (name == NULL) {
        return 0; // Memory allocation failed
    }
    memcpy(name, data + sizeof(int) + sizeof(NC_Dispatch), name_size);
    name[name_size] = '\0'; // Ensure null termination

    // Ensure that the name is not empty to maximize fuzzing effectiveness
    if (strlen(name) == 0) {
        strcpy(name, "default_name");
    }

    // Call the function-under-test
    nc_def_user_format_346(param1, &dispatch, name);

    // Clean up
    free(name);

    return 0;
}