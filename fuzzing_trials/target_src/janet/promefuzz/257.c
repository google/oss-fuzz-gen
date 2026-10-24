// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_table_init at janet.c:33101:13 in janet.h
// janet_table_clone at janet.c:33287:13 in janet.h
// janet_table_init_raw at janet.c:33106:13 in janet.h
// janet_table_weakk at janet.c:33126:13 in janet.h
// janet_table_weakkv at janet.c:33136:13 in janet.h
// janet_table at janet.c:33121:13 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <janet.h>

#define MAX_CAPACITY 1000

static void initialize_janet() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

int LLVMFuzzerTestOneInput_257(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return 0;

    initialize_janet();

    int32_t capacity = *((int32_t *)Data);
    capacity = capacity < 0 ? 0 : capacity % MAX_CAPACITY;

    JanetTable table;
    JanetTable *cloned_table = NULL;
    JanetTable *weak_table = NULL;
    JanetTable *weak_kv_table = NULL;
    JanetTable *new_table = NULL;

    // Fuzz janet_table_init
    janet_table_init(&table, capacity);

    // Fuzz janet_table_clone
    cloned_table = janet_table_clone(&table);

    // Fuzz janet_table_init_raw
    janet_table_init_raw(&table, capacity);

    // Fuzz janet_table_weakk
    weak_table = janet_table_weakk(capacity);

    // Fuzz janet_table_weakkv
    weak_kv_table = janet_table_weakkv(capacity);

    // Fuzz janet_table
    new_table = janet_table(capacity);

    // Clean up
    // Note: No manual deallocation required for cloned_table, weak_table, weak_kv_table, and new_table
    // as they are managed by the Janet garbage collector.

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

        LLVMFuzzerTestOneInput_257(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    