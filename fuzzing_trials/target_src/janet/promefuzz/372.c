// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_fiber at fiber.c:96:13 in janet.h
// janet_getfunction at janet.c:4521:1 in janet.h
// janet_optfunction at janet.c:4533:1 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_call at vm.c:1377:7 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static JanetFunction *create_dummy_function() {
    JanetFunction *func = (JanetFunction *)malloc(sizeof(JanetFunction));
    if (!func) return NULL;
    func->gc.flags = 0;
    func->def = (JanetFuncDef *)malloc(sizeof(JanetFuncDef));
    if (!func->def) {
        free(func);
        return NULL;
    }
    func->def->flags = 0;
    return func;
}

static void free_dummy_function(JanetFunction *func) {
    if (func) {
        if (func->def) free(func->def);
        free(func);
    }
}

int LLVMFuzzerTestOneInput_372(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t) * 3) return 0;

    janet_init();

    int32_t capacity = ((int32_t *)Data)[0];
    int32_t argc = ((int32_t *)Data)[1];
    int32_t index = ((int32_t *)Data)[2];
    Data += sizeof(int32_t) * 3;
    Size -= sizeof(int32_t) * 3;

    JanetFunction *callee = create_dummy_function();
    if (!callee) {
        janet_deinit();
        return 0;
    }

    Janet *argv = (Janet *)malloc(sizeof(Janet) * argc);
    if (!argv) {
        free_dummy_function(callee);
        janet_deinit();
        return 0;
    }
    memset(argv, 0, sizeof(Janet) * argc);

    if (capacity > 0 && argc <= capacity) {
        JanetFiber *fiber = janet_fiber(callee, capacity, argc, argv);
        if (fiber) {
            free(fiber);
        }
    }

    if (index >= 0 && index < argc) {
        JanetFunction *retrieved_func = janet_getfunction(argv, index);
        (void)retrieved_func;
    }

    JanetFunction *opt_func = janet_optfunction(argv, argc, index, callee);
    (void)opt_func;

    Janet wrapped = janet_wrap_function(callee);
    JanetFunction *unwrapped_func = janet_unwrap_function(wrapped);
    (void)unwrapped_func;

    if (unwrapped_func && argc <= capacity) {
        Janet result = janet_call(unwrapped_func, argc, argv);
        (void)result;
    }

    free(argv);
    free_dummy_function(callee);
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

        LLVMFuzzerTestOneInput_372(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    