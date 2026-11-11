// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_ev_default_threaded_callback at janet.c:11181:6 in janet.h
// janet_ev_post_event at janet.c:11064:6 in janet.h
// janet_ev_post_event at janet.c:11064:6 in janet.h
// janet_loop1_interrupt at janet.c:10456:6 in janet.h
// janet_ev_threaded_call at janet.c:11149:6 in janet.h
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static JanetEVGenericMessage dummy_threaded_subroutine(JanetEVGenericMessage args) {
    // Dummy threaded subroutine for testing purposes
    return args;
}

static void dummy_callback(JanetEVGenericMessage msg) {
    // Dummy callback function for testing purposes
}

int LLVMFuzzerTestOneInput_425(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetEVGenericMessage)) return 0;

    // Initialize a dummy JanetFiber
    JanetFiber fiber;
    memset(&fiber, 0, sizeof(JanetFiber)); // Ensure the fiber is properly initialized

    // Prepare a JanetEVGenericMessage with data from the fuzzer
    JanetEVGenericMessage msg;
    memcpy(&msg, Data, sizeof(JanetEVGenericMessage));

    // Set a valid fiber pointer
    msg.fiber = &fiber;

    // Fuzz janet_ev_default_threaded_callback
    janet_ev_default_threaded_callback(msg);

    // Fuzz janet_ev_post_event
    janet_ev_post_event(NULL, dummy_callback, msg);

    // Since we cannot instantiate JanetVM directly due to it being an incomplete type,
    // we will pass NULL to janet_loop1_interrupt and janet_ev_post_event as specified in
    // the function documentation to target the current thread.
    janet_ev_post_event(NULL, dummy_callback, msg);
    janet_loop1_interrupt(NULL);

    // Fuzz janet_ev_threaded_call
    janet_ev_threaded_call(dummy_threaded_subroutine, msg, dummy_callback);

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

        LLVMFuzzerTestOneInput_425(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    