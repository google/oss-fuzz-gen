// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_async_in_flight at janet.c:9142:6 in janet.h
// janet_loop_fiber at run.c:146:5 in janet.h
// janet_getfiber at janet.c:4520:1 in janet.h
// janet_pcall at vm.c:1617:13 in janet.h
// janet_fiber_can_resume at fiber.c:645:5 in janet.h
// janet_optfiber at janet.c:4532:1 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static JanetFiber *create_dummy_fiber() {
    JanetFiber *fiber = (JanetFiber *)malloc(sizeof(JanetFiber));
    if (fiber) {
        fiber->flags = 0;
        fiber->frame = 0;
        fiber->stackstart = 0;
        fiber->stacktop = 0;
        fiber->capacity = 0;
        fiber->maxstack = 0;
        fiber->env = NULL;
        fiber->data = NULL;
        fiber->child = NULL;
    }
    return fiber;
}

int LLVMFuzzerTestOneInput_260(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetFiber) + sizeof(JanetFunction)) {
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    JanetFiber *fiber = create_dummy_fiber();
    if (!fiber) {
        janet_deinit();
        return 0;
    }

    JanetFunction *fun = (JanetFunction *)(Data + sizeof(JanetFiber));
    Janet *argv = (Janet *)(Data + sizeof(JanetFiber) + sizeof(JanetFunction));

    // Test janet_async_in_flight
    janet_async_in_flight(fiber);

    // Test janet_loop_fiber
    int loop_result = janet_loop_fiber(fiber);

    // Test janet_getfiber
    JanetFiber *retrieved_fiber = janet_getfiber(argv, 0);

    // Test janet_pcall
    Janet out;
    JanetSignal signal = janet_pcall(fun, 1, argv, &out, &fiber);

    // Test janet_fiber_can_resume
    int can_resume = janet_fiber_can_resume(fiber);

    // Test janet_optfiber
    JanetFiber *opt_fiber = janet_optfiber(argv, 1, 0, fiber);

    // Cleanup
    free(fiber);

    // Deinitialize the Janet environment
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

        LLVMFuzzerTestOneInput_260(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    