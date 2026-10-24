#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "/src/hoextdown/src/stack.h"  // Correct path for hoedown_stack and related functions

// Remove 'extern "C"' since this is C code, not C++
int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
    hoedown_stack stack;
    hoedown_stack_init(&stack, 8);  // Initialize stack with a capacity of 8

    // Push some data onto the stack to ensure it is not empty
    for (size_t i = 0; i < size; ++i) {
        hoedown_stack_push(&stack, (void *)(uintptr_t)data[i]);
    }

    // Call the function-under-test
    void *popped_value = hoedown_stack_pop(&stack);

    // Clean up
    hoedown_stack_uninit(&stack);

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

    LLVMFuzzerTestOneInput_65(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
