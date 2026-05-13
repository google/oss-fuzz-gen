// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_dobytes at run.c:31:5 in janet.h
// janet_dostring at run.c:139:5 in janet.h
// janet_def_sm at janet.c:34099:6 in janet.h
// janet_def at janet.c:34105:6 in janet.h
// janet_env_lookup_into at marsh.c:104:6 in janet.h
// janet_var_sm at janet.c:34110:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static void initialize_janet_table(JanetTable *table) {
    memset(table, 0, sizeof(JanetTable));
    table->capacity = 8; // Arbitrary initial capacity
    table->data = (JanetKV *)calloc(table->capacity, sizeof(JanetKV));
}

int LLVMFuzzerTestOneInput_465(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there is at least some data

    // Initialize the Janet environment
    janet_init();
    JanetTable env;
    initialize_janet_table(&env);

    // Prepare a dummy output
    Janet out;
    out.u64 = 0; // Initialize Janet union to avoid undefined behavior

    // Fuzz janet_dobytes
    janet_dobytes(&env, Data, (int32_t)Size, "./dummy_file", &out);

    // Fuzz janet_dostring
    char *nullTerminatedString = (char *)malloc(Size + 1);
    if (nullTerminatedString) {
        memcpy(nullTerminatedString, Data, Size);
        nullTerminatedString[Size] = '\0'; // Ensure null termination
        janet_dostring(&env, nullTerminatedString, "./dummy_file", &out);
        free(nullTerminatedString);
    }

    // Fuzz janet_def_sm
    janet_def_sm(&env, "dummySymbol", out, "dummy documentation", "./dummy_file", 1);

    // Fuzz janet_def
    janet_def(&env, "dummyVar", out, "dummy documentation");

    // Fuzz janet_env_lookup_into
    JanetTable renv;
    initialize_janet_table(&renv);
    janet_env_lookup_into(&renv, &env, "prefix_", 1);

    // Fuzz janet_var_sm
    janet_var_sm(&env, "dummyVarSM", out, "dummy documentation", "./dummy_file", 1);

    // Clean up
    free(env.data);
    free(renv.data);
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

        LLVMFuzzerTestOneInput_465(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    