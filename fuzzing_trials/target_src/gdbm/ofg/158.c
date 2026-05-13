#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <gdbm.h>

// Define the gdbmarg structure
typedef struct gdbmarg {
    char *name;
    char *value;
} gdbmarg;

// Declare the gdbmarg_destroy_158 function
void gdbmarg_destroy(gdbmarg **arg_ptr);

int LLVMFuzzerTestOneInput_158(const uint8_t *data, size_t size) {
    // Declare a pointer to gdbmarg
    gdbmarg *arg = NULL;

    // Allocate memory for gdbmarg
    arg = (gdbmarg *)malloc(sizeof(gdbmarg));
    if (arg == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Initialize gdbmarg with some non-NULL values
    arg->name = (char *)malloc(size + 1);
    if (arg->name == NULL) {
        free(arg);
        return 0; // Exit if memory allocation fails
    }
    memcpy(arg->name, data, size);
    arg->name[size] = '\0';

    arg->value = (char *)malloc(size + 1);
    if (arg->value == NULL) {
        free(arg->name);
        free(arg);
        return 0; // Exit if memory allocation fails
    }
    memcpy(arg->value, data, size);
    arg->value[size] = '\0';

    // Create a pointer to the gdbmarg pointer
    gdbmarg **arg_ptr = &arg;

    // Call the function-under-test
    gdbmarg_destroy(arg_ptr);

    // Ensure the pointer is set to NULL after destruction
    if (*arg_ptr != NULL) {
        free(arg->name);
        free(arg->value);
        free(arg);
    }

    return 0;
}