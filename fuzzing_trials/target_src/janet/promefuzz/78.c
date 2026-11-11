// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_table_weakv at janet.c:33131:13 in janet.h
// janet_table_remove at janet.c:33222:7 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_sweep at gc.c:404:6 in janet.h
// janet_table_remove at janet.c:33222:7 in janet.h
// janet_table_weakv at janet.c:33131:13 in janet.h
// janet_cancel at janet.c:9395:6 in janet.h
// janet_gcpressure at gc.c:52:6 in janet.h
// janet_mark at gc.c:57:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "janet.h"

#define JANET_FIBER_FLAG_ROOT 1 // Define the flag since it's missing

static Janet random_janet() {
    Janet janet;
    switch (rand() % 4) {
        case 0: janet.u64 = rand(); break;
        case 1: janet.i64 = rand(); break;
        case 2: janet.number = (double)rand() / RAND_MAX; break;
        case 3: janet.pointer = NULL; break;
    }
    return janet;
}

static JanetTable* create_random_table() {
    int32_t capacity = rand() % 10;
    JanetTable *table = janet_table_weakv(capacity);
    for (int32_t i = 0; i < capacity; i++) {
        Janet key = random_janet();
        Janet value = random_janet();
        janet_table_remove(table, key); // Pre-populate with random data
    }
    return table;
}

static JanetFiber* create_random_fiber() {
    JanetFiber *fiber = (JanetFiber *)malloc(sizeof(JanetFiber));
    fiber->flags = JANET_FIBER_FLAG_ROOT;
    fiber->env = create_random_table();
    return fiber;
}

int LLVMFuzzerTestOneInput_78(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Initialize the Janet VM
    janet_init();

    // Fuzz janet_sweep
    janet_sweep();

    // Fuzz janet_table_remove
    JanetTable *table = create_random_table();
    if (table) {
        Janet key = random_janet();
        janet_table_remove(table, key);
    }

    // Fuzz janet_table_weakv
    int32_t capacity = Data[0] % 10;
    JanetTable *weak_table = janet_table_weakv(capacity);

    // Fuzz janet_cancel
    JanetFiber *fiber = create_random_fiber();
    if (fiber) {
        Janet value = random_janet();
        janet_cancel(fiber, value);
        free(fiber);
    }

    // Fuzz janet_gcpressure
    size_t s = Data[0];
    janet_gcpressure(s);

    // Fuzz janet_mark
    Janet x = random_janet();
    janet_mark(x);

    // Deinitialize the Janet VM
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

        LLVMFuzzerTestOneInput_78(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    