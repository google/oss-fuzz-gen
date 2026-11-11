// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_ev_threaded_await at janet.c:11220:6 in janet.h
// janet_gclock at gc.c:695:5 in janet.h
// janet_fiber_can_resume at fiber.c:645:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static JanetEVGenericMessage dummy_subroutine(JanetEVGenericMessage msg) {
    // Dummy subroutine for testing
    return msg;
}

int LLVMFuzzerTestOneInput_179(const uint8_t *Data, size_t Size) {
    // Initialize Janet VM before using any Janet functions
    janet_init();

    // Prepare environment for janet_ev_threaded_await
    JanetThreadedSubroutine fp = dummy_subroutine;
    int tag = 0;
    int argi = 0;
    void *argp = NULL;

    if (Size > 0) {
        tag = Data[0];
    }
    if (Size > 1) {
        argi = Data[1];
    }
    if (Size > 2) {
        argp = (void *)(Data + 2);
    }

    // Call janet_ev_threaded_await
    janet_ev_threaded_await(fp, tag, argi, argp);

    // Prepare environment for janet_gclock
    int gc_lock_result = janet_gclock();
    (void)gc_lock_result; // Suppress unused variable warning

    // Prepare environment for janet_fiber_can_resume
    JanetFiber fiber;
    fiber.flags = 0;
    fiber.frame = 0;
    fiber.stackstart = 0;
    fiber.stacktop = 0;
    fiber.capacity = 0;
    fiber.maxstack = 0;
    fiber.env = NULL;
    fiber.data = NULL;
    fiber.child = NULL;

    int can_resume = janet_fiber_can_resume(&fiber);
    (void)can_resume; // Suppress unused variable warning

    // Cleanup Janet VM after use
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

        LLVMFuzzerTestOneInput_179(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    