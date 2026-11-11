#include <sys/stat.h>
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

int LLVMFuzzerTestOneInput_910(const uint8_t *Data, size_t Size) {
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_910(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
