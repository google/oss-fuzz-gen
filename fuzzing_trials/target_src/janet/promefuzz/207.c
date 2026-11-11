// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_table_init at janet.c:33101:13 in janet.h
// janet_dobytes at run.c:31:5 in janet.h
// janet_dostring at run.c:139:5 in janet.h
// janet_def_sm at janet.c:34099:6 in janet.h
// janet_def at janet.c:34105:6 in janet.h
// janet_var at janet.c:34118:6 in janet.h
// janet_var_sm at janet.c:34110:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void initialize_janet_env(JanetTable *env) {
    // Properly initialize a Janet environment
    janet_init();
    janet_table_init(env, 0);
}

int LLVMFuzzerTestOneInput_207(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there is at least some data

    // Initialize the Janet environment
    JanetTable env;
    initialize_janet_env(&env);

    // Prepare a dummy output variable
    Janet out;

    // Prepare a source path
    const char *sourcePath = "./dummy_file";

    // Fuzz janet_dobytes
    janet_dobytes(&env, Data, (int32_t)Size, sourcePath, &out);

    // Fuzz janet_dostring if data is null-terminated
    if (Data[Size - 1] == '\0') {
        janet_dostring(&env, (const char *)Data, sourcePath, &out);
    }

    // Fuzz janet_def_sm
    if (Size > sizeof(Janet)) {
        Janet val;
        memcpy(&val, Data, sizeof(Janet));
        janet_def_sm(&env, "fuzz_symbol", val, "Fuzz documentation", sourcePath, 1);
    }

    // Fuzz janet_def
    if (Size > sizeof(Janet)) {
        Janet val;
        memcpy(&val, Data, sizeof(Janet));
        janet_def(&env, "fuzz_var", val, "Fuzz documentation");
    }

    // Fuzz janet_var
    if (Size > sizeof(Janet)) {
        Janet val;
        memcpy(&val, Data, sizeof(Janet));
        janet_var(&env, "fuzz_var", val, "Fuzz documentation");
    }

    // Fuzz janet_var_sm
    if (Size > sizeof(Janet)) {
        Janet val;
        memcpy(&val, Data, sizeof(Janet));
        janet_var_sm(&env, "fuzz_var_sm", val, "Fuzz documentation", sourcePath, 1);
    }

    // Cleanup Janet environment
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

        LLVMFuzzerTestOneInput_207(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    