// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_fiber at fiber.c:96:13 in janet.h
// janet_getfunction at janet.c:4521:1 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_call at vm.c:1377:7 in janet.h
// janet_optfunction at janet.c:4533:1 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
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
    func->def = func_def;
    func->envs[0] = NULL;
    return func;
}

static void initialize_janet() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

int LLVMFuzzerTestOneInput_704(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t) * 3) return 0;

    int32_t capacity = ((int32_t *)Data)[0];
    int32_t argc = ((int32_t *)Data)[1];
    int32_t index = ((int32_t *)Data)[2];
    Data += sizeof(int32_t) * 3;
    Size -= sizeof(int32_t) * 3;

    if (capacity <= 0 || argc < 0 || index < 0 || index >= argc) return 0;

    initialize_janet();

    JanetFunction *callee = create_dummy_function();
    if (!callee) return 0;

    Janet *argv = (Janet *)malloc(sizeof(Janet) * argc);
    if (!argv) {
        free(callee->def);
        free(callee);
        return 0;
    }

    for (int32_t i = 0; i < argc; i++) {
        argv[i].pointer = create_dummy_function();
    }

    JanetFiber *fiber = janet_fiber(callee, capacity, argc, argv);
    if (fiber) {
        JanetFunction *retrieved_func = janet_getfunction(argv, index);
        if (retrieved_func) {
            Janet wrapped = janet_wrap_function(retrieved_func);
            JanetFunction *unwrapped_func = janet_unwrap_function(wrapped);
            if (unwrapped_func) {
                janet_call(unwrapped_func, argc, argv);
            }
        }
        janet_optfunction(argv, argc, index, callee);
    }

    for (int32_t i = 0; i < argc; i++) {
        if (argv[i].pointer) {
            free(((JanetFunction *)argv[i].pointer)->def);
            free(argv[i].pointer);
        }
    }
    free(argv);
    free(callee->def);
    free(callee);
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

        LLVMFuzzerTestOneInput_704(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    