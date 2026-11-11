// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_stacktrace at debug.c:99:6 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_cancel at janet.c:9395:6 in janet.h
// janet_schedule at janet.c:9402:6 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_getfiber at janet.c:4520:1 in janet.h
// janet_stacktrace at debug.c:99:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static JanetFiber *create_dummy_fiber() {
    JanetFiber *fiber = (JanetFiber *)malloc(sizeof(JanetFiber));
    if (!fiber) return NULL;
    fiber->flags = 0;
    fiber->frame = 0;
    fiber->stackstart = 0;
    fiber->stacktop = 0;
    fiber->capacity = 10;
    fiber->maxstack = 10;
    fiber->env = NULL;
    fiber->data = (Janet *)malloc(sizeof(Janet) * fiber->capacity);
    fiber->child = NULL;
    return fiber;
}

static Janet create_dummy_janet() {
    Janet janet;
    janet.u64 = 0;
    return janet;
}

int LLVMFuzzerTestOneInput_511(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return 0;

    janet_init(); // Initialize the Janet VM

    JanetFiber *fiber = create_dummy_fiber();
    if (!fiber) {
        janet_deinit(); // Cleanup Janet VM
        return 0;
    }

    Janet err = create_dummy_janet();
    janet_stacktrace(fiber, err);

    JanetFiber *unwrapped_fiber = janet_unwrap_fiber(err);
    if (unwrapped_fiber) {
        janet_cancel(unwrapped_fiber, err);
        janet_schedule(unwrapped_fiber, err);
    }

    Janet wrapped_fiber = janet_wrap_fiber(fiber);
    JanetFiber *retrieved_fiber = janet_getfiber(&wrapped_fiber, 0);

    if (retrieved_fiber) {
        janet_stacktrace(retrieved_fiber, err);
    }

    free(fiber->data);
    free(fiber);

    janet_deinit(); // Cleanup Janet VM

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

        LLVMFuzzerTestOneInput_511(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    