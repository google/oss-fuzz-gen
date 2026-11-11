// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_table at janet.c:33121:13 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_cfuns_ext_prefix at janet.c:34272:6 in janet.h
// janet_def_sm at janet.c:34099:6 in janet.h
// janet_cfuns_ext at janet.c:34249:6 in janet.h
// janet_def at janet.c:34105:6 in janet.h
// janet_core_env at janet.c:7992:13 in janet.h
// janet_env_lookup_into at marsh.c:104:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void fuzz_janet_cfuns_ext_prefix(JanetTable *env, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    // Ensure the prefix is null-terminated within bounds
    char *prefix = (char *)malloc(Size + 1);
    if (!prefix) return;
    memcpy(prefix, Data, Size);
    prefix[Size] = '\0';

    JanetRegExt cfuns[] = {
        { "fuzz_func", NULL, "A fuzz function", __FILE__, __LINE__ },
        { NULL, NULL, NULL, NULL, 0 }
    };

    janet_cfuns_ext_prefix(env, prefix, cfuns);
    free(prefix);
}

static void fuzz_janet_def_sm(JanetTable *env, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    char *name = (char *)malloc(Size + 1);
    if (!name) return;
    memcpy(name, Data, Size);
    name[Size] = '\0';

    Janet val = { .u64 = 0 };
    const char *documentation = "Fuzz documentation";
    const char *source_file = __FILE__;
    int32_t source_line = __LINE__;

    janet_def_sm(env, name, val, documentation, source_file, source_line);
    free(name);
}

static void fuzz_janet_cfuns_ext(JanetTable *env, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    char *prefix = (char *)malloc(Size + 1);
    if (!prefix) return;
    memcpy(prefix, Data, Size);
    prefix[Size] = '\0';

    JanetRegExt cfuns[] = {
        { "fuzz_func", NULL, "A fuzz function", __FILE__, __LINE__ },
        { NULL, NULL, NULL, NULL, 0 }
    };

    janet_cfuns_ext(env, prefix, cfuns);
    free(prefix);
}

static void fuzz_janet_def(JanetTable *env, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    char *name = (char *)malloc(Size + 1);
    if (!name) return;
    memcpy(name, Data, Size);
    name[Size] = '\0';

    Janet val = { .u64 = 0 };
    const char *documentation = "Fuzz documentation";

    janet_def(env, name, val, documentation);
    free(name);
}

static void fuzz_janet_core_env(const uint8_t *Data, size_t Size) {
    JanetTable *replacements = NULL;
    if (Size >= sizeof(JanetTable)) {
        replacements = (JanetTable *)Data;
    }

    JanetTable *env = janet_core_env(replacements);
    (void)env;
}

static void fuzz_janet_env_lookup_into(JanetTable *renv, const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    char *prefix = (char *)malloc(Size + 1);
    if (!prefix) return;
    memcpy(prefix, Data, Size);
    prefix[Size] = '\0';

    JanetTable *env = NULL;
    int recurse = Data[0] % 2;

    janet_env_lookup_into(renv, env, prefix, recurse);
    free(prefix);
}

int LLVMFuzzerTestOneInput_689(const uint8_t *Data, size_t Size) {
    janet_init(); // Ensure the Janet VM is initialized

    JanetTable *dummy_env = janet_table(10); // Use janet_table to create a valid environment
    fuzz_janet_cfuns_ext_prefix(dummy_env, Data, Size);
    fuzz_janet_def_sm(dummy_env, Data, Size);
    fuzz_janet_cfuns_ext(dummy_env, Data, Size);
    fuzz_janet_def(dummy_env, Data, Size);
    fuzz_janet_core_env(Data, Size);
    fuzz_janet_env_lookup_into(dummy_env, Data, Size);

    janet_deinit(); // Clean up the Janet VM
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

        LLVMFuzzerTestOneInput_689(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    