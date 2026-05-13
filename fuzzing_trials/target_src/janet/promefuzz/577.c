// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_ev_inc_refcount at janet.c:9597:6 in janet.h
// janet_ev_post_event at janet.c:11064:6 in janet.h
// janet_async_end at janet.c:9121:6 in janet.h
// janet_ev_threaded_call at janet.c:11149:6 in janet.h
// janet_ev_dec_refcount at janet.c:9601:6 in janet.h
// janet_ev_default_threaded_callback at janet.c:11181:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void dummy_ev_callback(JanetFiber *fiber, JanetAsyncEvent event) {
    // Dummy event callback for testing
}

static JanetEVGenericMessage dummy_threaded_subroutine(JanetEVGenericMessage arguments) {
    // Dummy threaded subroutine for testing
    return arguments;
}

static void dummy_threaded_callback(JanetEVGenericMessage return_value) {
    // Dummy threaded callback for testing
}

int LLVMFuzzerTestOneInput_577(const uint8_t *Data, size_t Size) {
    // Initialize a dummy JanetFiber
    JanetFiber fiber = {0};

    // Initialize a JanetStream and assign it to the fiber
    JanetStream stream = {0};
    fiber.ev_stream = &stream;

    // Initialize a JanetEVGenericMessage
    JanetEVGenericMessage msg = {0};
    msg.fiber = &fiber;

    // Test janet_ev_inc_refcount
    janet_ev_inc_refcount();

    // Test janet_ev_post_event
    janet_ev_post_event(NULL, dummy_threaded_callback, msg);

    // Test janet_async_end
    fiber.ev_callback = dummy_ev_callback;
    janet_async_end(&fiber);

    // Test janet_ev_threaded_call
    janet_ev_threaded_call(dummy_threaded_subroutine, msg, dummy_threaded_callback);

    // Test janet_ev_dec_refcount
    janet_ev_dec_refcount();

    // Test janet_ev_default_threaded_callback
    janet_ev_default_threaded_callback(msg);

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

        LLVMFuzzerTestOneInput_577(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    