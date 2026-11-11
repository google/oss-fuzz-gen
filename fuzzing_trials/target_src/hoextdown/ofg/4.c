#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    void **item;
    size_t size;
    size_t asize;
} hoedown_stack;

void hoedown_stack_grow(hoedown_stack *st, size_t new_size);

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    // Initialize a hoedown_stack object
    hoedown_stack stack;
    stack.size = 0;
    stack.asize = 8;  // Initial allocation size
    stack.item = (void **)malloc(stack.asize * sizeof(void *));
    if (stack.item == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Ensure the stack is not empty
    for (size_t i = 0; i < stack.asize; i++) {
        stack.item[i] = (void *)(uintptr_t)i; // Assign non-NULL values
    }
    stack.size = stack.asize;

    // Determine a new size for the stack based on input data
    size_t new_size = size > 0 ? (size_t)data[0] : 1; // Use the first byte of data as new size

    // Call the function-under-test
    hoedown_stack_grow(&stack, new_size);

    // Clean up
    free(stack.item);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
