// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_string at string.c:49:16 in janet.h
// janet_nanbox_from_double at janet.c:37710:7 in janet.h
// janet_nanbox_from_cpointer at janet.c:37698:7 in janet.h
// janet_table_put at janet.c:33237:6 in janet.h
// janet_string at string.c:49:16 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_table_merge_table at janet.c:33313:6 in janet.h
// janet_table_get_ex at janet.c:33200:7 in janet.h
// janet_cfuns_prefix at janet.c:34259:6 in janet.h
// janet_cfuns_ext at janet.c:34249:6 in janet.h
// janet_core_lookup_table at janet.c:8037:13 in janet.h
// janet_cfuns at janet.c:34239:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_table at janet.c:33121:13 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static JanetTable *create_dummy_table(void) {
    JanetTable *table = janet_table(10);
    JanetString key = janet_string((const uint8_t *)"key", 3);
    Janet value = janet_wrap_integer(42);
    janet_table_put(table, janet_wrap_string(key), value);
    return table;
}

static Janet create_dummy_key(void) {
    return janet_wrap_string(janet_string((const uint8_t *)"key", 3));
}

int LLVMFuzzerTestOneInput_300(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    janet_init();

    // Fuzz janet_table_merge_table
    JanetTable *table1 = create_dummy_table();
    JanetTable *table2 = create_dummy_table();
    janet_table_merge_table(table1, table2);

    // Fuzz janet_table_get_ex
    JanetTable *which = NULL;
    Janet key = create_dummy_key();
    Janet value = janet_table_get_ex(table1, key, &which);

    // Fuzz janet_cfuns_prefix
    const char *prefix = "test";
    JanetReg cfuns[] = {
        {NULL, NULL, NULL}
    };
    janet_cfuns_prefix(table1, prefix, cfuns);

    // Fuzz janet_cfuns_ext
    JanetRegExt cfuns_ext[] = {
        {NULL, NULL, NULL, NULL, 0}
    };
    janet_cfuns_ext(table1, prefix, cfuns_ext);

    // Fuzz janet_core_lookup_table
    JanetTable *core_table = janet_core_lookup_table(table1);

    // Fuzz janet_cfuns
    janet_cfuns(core_table, prefix, cfuns);

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

        LLVMFuzzerTestOneInput_300(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    