// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_stack_init at stack.c:10:1 in stack.h
// hoedown_stack_grow at stack.c:32:1 in stack.h
// hoedown_stack_push at stack.c:49:1 in stack.h
// hoedown_stack_top at stack.c:71:1 in stack.h
// hoedown_stack_pop at stack.c:60:1 in stack.h
// hoedown_stack_uninit at stack.c:24:1 in stack.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include "stack.h"

#define MAX_INITIAL_SIZE 1024
#define MAX_NEOSZ 2048

static void fuzz_hoedown_stack_init(hoedown_stack *st, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return;
    size_t initial_size = *((size_t*)Data) % MAX_INITIAL_SIZE;
    hoedown_stack_init(st, initial_size);
}

static void fuzz_hoedown_stack_grow(hoedown_stack *st, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return;
    size_t neosz = *((size_t*)Data) % MAX_NEOSZ;
    hoedown_stack_grow(st, neosz);
}

static void fuzz_hoedown_stack_push(hoedown_stack *st, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(void*)) return;
    void *item = (void*)Data;
    hoedown_stack_push(st, item);
}

int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    hoedown_stack stack;
    memset(&stack, 0, sizeof(stack)); // Ensure stack is zero-initialized

    fuzz_hoedown_stack_init(&stack, Data, Size);

    if (Size > sizeof(size_t)) {
        fuzz_hoedown_stack_grow(&stack, Data + sizeof(size_t), Size - sizeof(size_t));
    }

    if (Size > 2 * sizeof(size_t)) {
        fuzz_hoedown_stack_push(&stack, Data + 2 * sizeof(size_t), Size - 2 * sizeof(size_t));
    }

    void *top_item = hoedown_stack_top(&stack);
    (void)top_item; // Suppress unused variable warning

    void *popped_item = hoedown_stack_pop(&stack);
    (void)popped_item; // Suppress unused variable warning

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

        LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    