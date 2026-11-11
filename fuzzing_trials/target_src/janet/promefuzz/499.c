// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_core_env at janet.c:7992:13 in janet.h
// janet_table_get_ex at janet.c:33200:7 in janet.h
// janet_core_env at janet.c:7992:13 in janet.h
// janet_cfuns_prefix at janet.c:34259:6 in janet.h
// janet_core_env at janet.c:7992:13 in janet.h
// janet_cfuns_ext at janet.c:34249:6 in janet.h
// janet_core_env at janet.c:7992:13 in janet.h
// janet_core_env at janet.c:7992:13 in janet.h
// janet_core_env at janet.c:7992:13 in janet.h
// janet_core_lookup_table at janet.c:8037:13 in janet.h
// janet_core_env at janet.c:7992:13 in janet.h
// janet_cfuns at janet.c:34239:6 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "janet.h"

static void fuzz_janet_table_get_ex(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;

    JanetTable *table = janet_core_env(NULL);
    Janet key = *(const Janet *)Data;
    JanetTable *which = NULL;

    janet_table_get_ex(table, key, &which);
}

static void fuzz_janet_cfuns_prefix(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetReg)) return;

    JanetTable *env = janet_core_env(NULL);
    const char *regprefix = "fuzz_prefix";
    const JanetReg *cfuns = (const JanetReg *)Data;

    janet_cfuns_prefix(env, regprefix, cfuns);
}

static void fuzz_janet_cfuns_ext(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetRegExt)) return;

    JanetTable *env = janet_core_env(NULL);
    const char *regprefix = "fuzz_ext_prefix";
    const JanetRegExt *cfuns = (const JanetRegExt *)Data;

    janet_cfuns_ext(env, regprefix, cfuns);
}

static void fuzz_janet_core_env(const uint8_t *Data, size_t Size) {
    (void)Data; // Unused
    (void)Size; // Unused

    JanetTable *replacements = janet_core_env(NULL);
    janet_core_env(replacements);
}

static void fuzz_janet_core_lookup_table(const uint8_t *Data, size_t Size) {
    (void)Data; // Unused
    (void)Size; // Unused

    JanetTable *replacements = janet_core_env(NULL);
    janet_core_lookup_table(replacements);
}

static void fuzz_janet_cfuns(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetReg)) return;

    JanetTable *env = janet_core_env(NULL);
    const char *regprefix = "fuzz_cfuns_prefix";
    const JanetReg *cfuns = (const JanetReg *)Data;

    janet_cfuns(env, regprefix, cfuns);
}

int LLVMFuzzerTestOneInput_499(const uint8_t *Data, size_t Size) {
    janet_init();

    fuzz_janet_table_get_ex(Data, Size);
    fuzz_janet_cfuns_prefix(Data, Size);
    fuzz_janet_cfuns_ext(Data, Size);
    fuzz_janet_core_env(Data, Size);
    fuzz_janet_core_lookup_table(Data, Size);
    fuzz_janet_cfuns(Data, Size);

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

        LLVMFuzzerTestOneInput_499(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    