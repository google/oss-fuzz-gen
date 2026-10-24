// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_ev_default_threaded_callback at janet.c:11181:6 in janet.h
// janet_ev_post_event at janet.c:11064:6 in janet.h
// janet_loop1_interrupt at janet.c:10456:6 in janet.h
// janet_ev_threaded_call at janet.c:11149:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include "janet.h"

static JanetEVGenericMessage dummy_threaded_subroutine(JanetEVGenericMessage arguments) {
    // Dummy threaded subroutine for testing
    return arguments;
}

static void dummy_callback(JanetEVGenericMessage msg) {
    // Dummy callback function for testing
}

int LLVMFuzzerTestOneInput_296(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetEVGenericMessage)) return 0;

    // Prepare a dummy JanetEVGenericMessage
    JanetEVGenericMessage msg;
    JanetFiber fiber;
    fiber.gc.flags = 0;
    fiber.flags = 0;
    msg.fiber = &fiber;

    // Test janet_ev_default_threaded_callback
    janet_ev_default_threaded_callback(msg);

    // Prepare a dummy JanetVM pointer
    JanetVM *vm = NULL;

    // Test janet_ev_post_event
    janet_ev_post_event(vm, dummy_callback, msg);

    // Test janet_loop1_interrupt
    janet_loop1_interrupt(vm);

    // Prepare dummy arguments for janet_ev_threaded_call
    JanetEVGenericMessage arguments;
    arguments.fiber = &fiber;

    // Test janet_ev_threaded_call
    janet_ev_threaded_call(dummy_threaded_subroutine, arguments, dummy_callback);

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

        LLVMFuzzerTestOneInput_296(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    