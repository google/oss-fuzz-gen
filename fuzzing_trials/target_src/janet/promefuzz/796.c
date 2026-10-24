// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_cfuns_ext_prefix at janet.c:34272:6 in janet.h
// janet_cfuns_ext at janet.c:34249:6 in janet.h
// janet_def at janet.c:34105:6 in janet.h
// janet_core_env at janet.c:7992:13 in janet.h
// janet_env_lookup_into at marsh.c:104:6 in janet.h
// janet_var_sm at janet.c:34110:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_table at janet.c:33121:13 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

// Function prototypes for initializing Janet types
static JanetTable *init_janet_table(void);
static JanetRegExt *init_janet_regext_array(const uint8_t *Data, size_t Size);
static void cleanup_janet_regext_array(JanetRegExt *cfuns);

// Entry point for the fuzzer
int LLVMFuzzerTestOneInput_796(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize the Janet runtime
    janet_init();

    // Initialize a JanetTable environment
    JanetTable *env = init_janet_table();

    // Initialize a prefix string
    const char *prefix = "fuzz_prefix";

    // Initialize a JanetRegExt array
    JanetRegExt *cfuns = init_janet_regext_array(Data, Size);

    // Fuzz janet_cfuns_ext_prefix
    janet_cfuns_ext_prefix(env, prefix, cfuns);

    // Fuzz janet_cfuns_ext
    janet_cfuns_ext(env, prefix, cfuns);

    // Fuzz janet_def
    Janet val;
    val.i64 = 42;
    janet_def(env, "fuzz_var", val, "Fuzz variable documentation");

    // Fuzz janet_core_env
    JanetTable *core_env = janet_core_env(env);

    // Fuzz janet_env_lookup_into
    janet_env_lookup_into(core_env, env, prefix, 1);

    // Fuzz janet_var_sm
    janet_var_sm(env, "fuzz_var_sm", val, "Fuzz var sm documentation", "fuzz_source.janet", 123);

    // Cleanup
    cleanup_janet_regext_array(cfuns);

    // Deinitialize the Janet runtime
    janet_deinit();

    return 0;
}

// Helper function to initialize a JanetTable
static JanetTable *init_janet_table(void) {
    JanetTable *table = janet_table(0);
    return table;
}

// Helper function to initialize a JanetRegExt array
static JanetRegExt *init_janet_regext_array(const uint8_t *Data, size_t Size) {
    size_t num_entries = Size / sizeof(JanetRegExt);
    JanetRegExt *array = (JanetRegExt *)malloc((num_entries + 1) * sizeof(JanetRegExt));
    if (array) {
        for (size_t i = 0; i < num_entries; i++) {
            array[i].name = "fuzz_cfun";
            array[i].cfun = NULL; // Assign appropriate function pointer if needed
            array[i].documentation = "Fuzz cfun documentation";
            array[i].source_file = "fuzz_source.janet";
            array[i].source_line = 123;
        }
        // Null-terminate the array
        array[num_entries].name = NULL;
    }
    return array;
}

// Helper function to cleanup a JanetRegExt array
static void cleanup_janet_regext_array(JanetRegExt *cfuns) {
    if (cfuns) {
        free(cfuns);
    }
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

        LLVMFuzzerTestOneInput_796(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    