#include <gdbm.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Mock definition of struct gdbmarg
struct gdbmarg {
    char *name;
};

// Mock definition of gdbmarg_destroy_157 function
void gdbmarg_destroy_157(struct gdbmarg **arg_ptr) {
    if (arg_ptr && *arg_ptr) {
        if ((*arg_ptr)->name) {
            free((*arg_ptr)->name);
        }
        free(*arg_ptr);
        *arg_ptr = NULL;
    }
}

int LLVMFuzzerTestOneInput_157(const uint8_t *data, size_t size) {
    struct gdbmarg *arg = NULL;
    struct gdbmarg **arg_ptr = &arg;

    // Simulate some initialization of gdbmarg structure
    if (size > 0) {
        arg = (struct gdbmarg *)malloc(sizeof(struct gdbmarg));
        if (arg != NULL) {
            arg->name = (char *)malloc(size + 1);
            if (arg->name != NULL) {
                memcpy(arg->name, data, size);
                arg->name[size] = '\0'; // Null-terminate the string
            }
        }
    }

    // Call the function-under-test
    gdbmarg_destroy_157(arg_ptr);

    // Clean up
    if (arg != NULL) {
        if (arg->name != NULL) {
            free(arg->name);
        }
        free(arg);
    }

    return 0;
}