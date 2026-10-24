// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_table_remove at janet.c:33222:7 in janet.h
// janet_compile_lint at compile.c:1165:20 in janet.h
// janet_put at value.c:764:6 in janet.h
// janet_compile at compile.c:1199:20 in janet.h
// janet_get at value.c:514:7 in janet.h
// janet_def at janet.c:34105:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void initialize_janet_table(JanetTable *table) {
    table->count = 0;
    table->capacity = 8;
    table->deleted = 0;
    table->data = (JanetKV *)malloc(sizeof(JanetKV) * table->capacity);
    for (int i = 0; i < table->capacity; i++) {
        table->data[i].key.u64 = 0;
        table->data[i].value.u64 = 0;
    }
}

static void cleanup_janet_table(JanetTable *table) {
    free(table->data);
}

int LLVMFuzzerTestOneInput_615(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize Janet VM
    janet_init();

    // Prepare dummy data
    JanetTable env;
    initialize_janet_table(&env);

    JanetArray lints;
    lints.capacity = 8;
    lints.data = (Janet *)malloc(sizeof(Janet) * lints.capacity);

    Janet key, value;
    key.u64 = Data[0];
    value.u64 = Data[0];

    // Fuzz janet_table_remove
    janet_table_remove(&env, key);

    // Fuzz janet_compile_lint
    Janet source;
    source.u64 = Data[0];
    JanetString where = (JanetString)"dummy_location";
    janet_compile_lint(source, &env, where, &lints);

    // Fuzz janet_put
    Janet ds;
    ds.u64 = Data[0];
    janet_put(ds, key, value);

    // Fuzz janet_compile
    janet_compile(source, &env, where);

    // Fuzz janet_get
    janet_get(ds, key);

    // Fuzz janet_def
    janet_def(&env, "dummy_name", value, "dummy_documentation");

    // Cleanup
    cleanup_janet_table(&env);
    free(lints.data);

    // Deinitialize Janet VM
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

        LLVMFuzzerTestOneInput_615(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    