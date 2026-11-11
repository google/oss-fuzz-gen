#include <stdint.h>
#include <stdlib.h>
#include "/src/hoextdown/src/stack.h"  // Correct path for hoedown_stack

int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    hoedown_stack stack;

    // Initialize the stack with some reasonable values
    hoedown_stack_init(&stack, 8); // Corrected to match the function signature

    // Fuzzing: manipulate the stack with the provided data
    for (size_t i = 0; i < size; i++) {
        hoedown_stack_push(&stack, (void *)(uintptr_t)data[i]);
    }

    // Call the function under test
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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
