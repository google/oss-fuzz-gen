// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_table at janet.c:33121:13 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_cfuns_ext_prefix at janet.c:34272:6 in janet.h
// janet_def_sm at janet.c:34099:6 in janet.h
// janet_cfuns_ext at janet.c:34249:6 in janet.h
// janet_env_lookup_into at marsh.c:104:6 in janet.h
// janet_core_env at janet.c:7992:13 in janet.h
// janet_var_sm at janet.c:34110:6 in janet.h
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

static JanetTable *create_dummy_table() {
    JanetTable *table = janet_table(10);
    return table;
}

static JanetRegExt *create_dummy_regext() {
    static JanetRegExt regext[] = {
        { "dummy_function", NULL, "Dummy documentation", "dummy_source", 1 },
        { NULL, NULL, NULL, NULL, 0 }
    };
    return regext;
}

int LLVMFuzzerTestOneInput_529(const uint8_t *Data, size_t Size) {
    // Initialize the Janet VM
    janet_init();

    // Prepare dummy Janet environment
    JanetTable *env = create_dummy_table();
    JanetTable *renv = create_dummy_table();
    JanetRegExt *cfuns = create_dummy_regext();
    char prefix[32] = "fuzz_prefix";
    char name[32] = "fuzz_name";
    char doc[32] = "fuzz_doc";
    char source_file[32] = "fuzz_source";

    // Ensure null-termination for strings
    if (Size > 0) {
        size_t copy_size = (Size < 31) ? Size : 31;
        memcpy(prefix, Data, copy_size);
        prefix[copy_size] = '\0';
        memcpy(name, Data, copy_size);
        name[copy_size] = '\0';
        memcpy(doc, Data, copy_size);
        doc[copy_size] = '\0';
        memcpy(source_file, Data, copy_size);
        source_file[copy_size] = '\0';
    }

    // Call janet_cfuns_ext_prefix
    janet_cfuns_ext_prefix(env, prefix, cfuns);

    // Call janet_def_sm
    Janet val;
    val.u64 = 42; // Dummy value
    janet_def_sm(env, name, val, doc, source_file, 10);

    // Call janet_cfuns_ext
    janet_cfuns_ext(env, prefix, cfuns);

    // Call janet_env_lookup_into
    janet_env_lookup_into(renv, env, prefix, 1);

    // Call janet_core_env
    JanetTable *core_env = janet_core_env(env);

    // Call janet_var_sm
    janet_var_sm(env, name, val, doc, source_file, 20);

    // Cleanup
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

        LLVMFuzzerTestOneInput_529(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    