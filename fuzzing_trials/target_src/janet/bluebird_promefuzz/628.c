#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static JanetFiber *create_fiber() {
    JanetFiber *fiber = malloc(sizeof(JanetFiber));
    if (fiber) {
        memset(fiber, 0, sizeof(JanetFiber));
        fiber->env = malloc(sizeof(JanetTable));
        if (fiber->env) {
            memset(fiber->env, 0, sizeof(JanetTable));
        }
    }
    return fiber;
}

static void destroy_fiber(JanetFiber *fiber) {
    if (fiber) {
        if (fiber->env) {
            free(fiber->env);
        }
        free(fiber);
    }
}

static int is_valid_janet(Janet value) {
    // Example validation: Ensure the pointer is not null for types that use pointers
    if (value.pointer == NULL) {
        return 0;
    }
    return 1;
}

int LLVMFuzzerTestOneInput_628(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) {
        return 0;
    }

    // Initialize the Janet VM
    janet_init();

    // Prepare a dummy fiber
    JanetFiber *fiber = create_fiber();
    if (!fiber) {
        janet_deinit();
        return 0;
    }

    // Prepare a Janet value from input data
    Janet value;
    memcpy(&value, Data, sizeof(Janet));

    // Validate the Janet value before using it
    if (!is_valid_janet(value)) {
        destroy_fiber(fiber);
        janet_deinit();
        return 0;
    }

    // Test janet_wrap_fiber
    Janet wrapped_fiber = janet_wrap_fiber(fiber);

    // Test janet_unwrap_fiber
    JanetFiber *unwrapped_fiber = janet_unwrap_fiber(wrapped_fiber);

    // Check if unwrapped fiber is valid
    if (unwrapped_fiber == fiber) {
        // Test janet_stacktrace with a valid error string
        Janet err_str = janet_cstringv("error");
        janet_stacktrace(fiber, err_str);

        // Test janet_schedule_signal with a dummy signal
        janet_schedule_signal(fiber, value, (JanetSignal)(Data[0] % 256));

        // Test janet_cancel
        janet_cancel(fiber, value);

        // Test janet_schedule
        janet_schedule(fiber, value);
    }

    // Cleanup
    destroy_fiber(fiber);

    // Deinitialize the Janet VM
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_628(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
