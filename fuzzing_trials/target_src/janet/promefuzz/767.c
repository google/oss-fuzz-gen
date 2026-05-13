// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_loop_fiber at run.c:146:5 in janet.h
// janet_fiber_can_resume at fiber.c:645:5 in janet.h
// janet_getfiber at janet.c:4520:1 in janet.h
// janet_optfiber at janet.c:4532:1 in janet.h
// janet_cryptorand at janet.c:34711:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
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
        fiber->data = (Janet *)malloc(10 * sizeof(Janet));
        fiber->child = NULL;
    }
    return fiber;
}

static void cleanup_fiber(JanetFiber *fiber) {
    if (fiber) {
        free(fiber->data);
        free(fiber);
    }
}

int LLVMFuzzerTestOneInput_767(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize Janet
    janet_init();

    // Initialize a dummy fiber
    JanetFiber *fiber = create_dummy_fiber();
    if (!fiber) {
        janet_deinit();
        return 0;
    }

    // Fuzz janet_loop_fiber
    janet_loop_fiber(fiber);

    // Fuzz janet_fiber_can_resume
    int can_resume = janet_fiber_can_resume(fiber);

    // Prepare dummy Janet array for argument
    Janet argv[2];
    argv[0].pointer = fiber;
    argv[1].pointer = NULL;

    // Fuzz janet_getfiber
    JanetFiber *retrieved_fiber = janet_getfiber(argv, 0);

    // Fuzz janet_optfiber
    JanetFiber *opt_fiber = janet_optfiber(argv, 2, 0, fiber);

    // Fuzz janet_cryptorand
    uint8_t rand_buffer[10];
    int rand_result = janet_cryptorand(rand_buffer, sizeof(rand_buffer));

    // Write some data to a dummy file for any file-based operations
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }

    // Cleanup
    cleanup_fiber(fiber);
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

        LLVMFuzzerTestOneInput_767(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    