// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_getfiber at janet.c:4520:1 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_cancel at janet.c:9395:6 in janet.h
// janet_schedule at janet.c:9402:6 in janet.h
// janet_stacktrace at debug.c:99:6 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

static JanetFiber *create_dummy_fiber() {
    JanetFiber *fiber = (JanetFiber *)malloc(sizeof(JanetFiber));
    if (fiber) {
        fiber->flags = 0;
        fiber->frame = 0;
        fiber->stackstart = 0;
        fiber->stacktop = 0;
        fiber->capacity = 10;
        fiber->maxstack = 100;
        fiber->env = NULL;
        fiber->data = (Janet *)malloc(fiber->capacity * sizeof(Janet));
        fiber->child = NULL;
        fiber->last_value = (Janet){.u64 = 0};
    }
    return fiber;
}

static void free_dummy_fiber(JanetFiber *fiber) {
    if (fiber) {
        free(fiber->data);
        free(fiber);
    }
}

int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return 0;

    // Initialize Janet VM
    janet_init();

    // Prepare a dummy Janet array
    Janet argv[1];
    argv[0].u64 = *(uint64_t *)Data;

    // Test janet_getfiber
    JanetFiber *fiber1 = NULL;
    if (janet_checktype(argv[0], JANET_FIBER)) {
        fiber1 = janet_getfiber(argv, 0);
    }

    // Test janet_unwrap_fiber
    JanetFiber *fiber2 = NULL;
    if (janet_checktype(argv[0], JANET_FIBER)) {
        fiber2 = janet_unwrap_fiber(argv[0]);
    }

    // Create a dummy fiber for testing
    JanetFiber *fiber3 = create_dummy_fiber();
    if (!fiber3) {
        janet_deinit();
        return 0;
    }

    // Test janet_cancel
    if (fiber3) {
        janet_cancel(fiber3, argv[0]);
    }

    // Test janet_schedule
    if (fiber3) {
        janet_schedule(fiber3, argv[0]);
    }

    // Test janet_stacktrace
    if (fiber3 && janet_checktype(argv[0], JANET_STRING)) {
        janet_stacktrace(fiber3, argv[0]);
    }

    // Test janet_wrap_fiber
    if (fiber3) {
        Janet wrapped_fiber = janet_wrap_fiber(fiber3);
    }

    // Cleanup
    free_dummy_fiber(fiber3);

    // Deinitialize Janet VM
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

        if(size < 1 + 1)
            exit(0);

        data = (uint8_t *)malloc((size_t)size);
        if(data == NULL)
            exit(0);

        if(fread(data, (size_t)size, 1, f) != 1)
            exit(0);

        LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    