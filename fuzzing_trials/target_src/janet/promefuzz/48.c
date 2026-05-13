// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_fiber at fiber.c:96:13 in janet.h
// janet_getfunction at janet.c:4521:1 in janet.h
// janet_optfunction at janet.c:4533:1 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_call at vm.c:1377:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static JanetFunction *create_dummy_function() {
    JanetFuncDef *func_def = (JanetFuncDef *)malloc(sizeof(JanetFuncDef));
    if (!func_def) return NULL;
    memset(func_def, 0, sizeof(JanetFuncDef));
    JanetFunction *func = (JanetFunction *)malloc(sizeof(JanetFunction) + sizeof(JanetFuncEnv *));
    if (!func) {
        free(func_def);
        return NULL;
    }
    memset(func, 0, sizeof(JanetFunction) + sizeof(JanetFuncEnv *));
    func->def = func_def;
    return func;
}

static void initialize_janet_vm() {
    janet_init();
}

static void cleanup_janet_vm() {
    janet_deinit();
}

int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t) * 3) return 0;

    initialize_janet_vm();

    int32_t capacity = ((int32_t *)Data)[0];
    int32_t argc = ((int32_t *)Data)[1];
    int32_t n = ((int32_t *)Data)[2];

    if (capacity <= 0 || argc < 0 || argc > capacity) {
        cleanup_janet_vm();
        return 0;
    }

    Janet *argv = (Janet *)malloc(sizeof(Janet) * capacity);
    if (!argv) {
        cleanup_janet_vm();
        return 0;
    }
    memset(argv, 0, sizeof(Janet) * capacity);

    JanetFunction *callee = create_dummy_function();
    if (!callee) {
        free(argv);
        cleanup_janet_vm();
        return 0;
    }

    JanetFiber *fiber = janet_fiber(callee, capacity, argc, argv);
    if (fiber) {
        JanetFunction *retrieved_func = janet_getfunction(argv, n);
        JanetFunction *opt_func = janet_optfunction(argv, argc, n, callee);
        Janet wrapped = janet_wrap_function(callee);
        JanetFunction *unwrapped_func = janet_unwrap_function(wrapped);
        if (unwrapped_func) {
            janet_call(unwrapped_func, argc, argv);
        }
    }

    free(callee->def);
    free(callee);
    free(argv);

    cleanup_janet_vm();
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

        LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    