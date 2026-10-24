#include <sys/stat.h>
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

int LLVMFuzzerTestOneInput_67(const uint8_t *Data, size_t Size) {
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_67(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
