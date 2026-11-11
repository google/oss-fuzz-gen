#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming the structure definitions for gdbmarglist and gdbmarg are available
struct gdbmarglist {
    struct gdbmarg *head;
    struct gdbmarg *tail;
};

struct gdbmarg {
    char *data;
    struct gdbmarg *next;
};

// Function-under-test
void gdbmarglist_add(struct gdbmarglist *list, struct gdbmarg *arg);

int LLVMFuzzerTestOneInput_145(const uint8_t *data, size_t size) {
    // Initialize gdbmarglist
    struct gdbmarglist list;
    list.head = NULL;
    list.tail = NULL;

    // Initialize gdbmarg
    struct gdbmarg arg;
    arg.next = NULL;

    // Allocate and copy data to gdbmarg's data field
    if (size > 0) {
        arg.data = (char *)malloc(size + 1);
        if (arg.data == NULL) {
            return 0; // Exit if memory allocation fails
        }
        memcpy(arg.data, data, size);
        arg.data[size] = '\0'; // Null-terminate the data
    } else {
        arg.data = strdup("default"); // Provide a default value if size is 0
    }

    // Call the function-under-test
    gdbmarglist_add(&list, &arg);

    // Free allocated memory
    free(arg.data);

    return 0;
}