#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_576(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to create a tuple
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Calculate the number of elements in the tuple
    size_t num_elements = size / sizeof(Janet);

    // Allocate memory for the tuple
    Janet *elements = (Janet *)malloc(num_elements * sizeof(Janet));
    if (!elements) {
        return 0;
    }

    // Initialize the Janet runtime before using any Janet functions
    janet_init();

    // Initialize the tuple elements with data
    for (size_t i = 0; i < num_elements; i++) {
        elements[i] = janet_wrap_integer((int32_t)data[i]);
    }

    // Create a JanetTuple from the elements
    JanetTuple tuple = janet_tuple_n(elements, num_elements);

    // Access the first element of the tuple
    if (num_elements > 0) {
        Janet head = tuple[0]; // Access the tuple instead of elements directly

        // Example usage of head, e.g., printing or further processing
        // This is just a placeholder to ensure the head is accessed
        janet_gcroot(head);
    }

    // Clean up
    free(elements);

    // Deinitialize the Janet runtime
    janet_deinit();

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_576(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
