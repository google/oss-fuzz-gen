// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_table at janet.c:33121:13 in janet.h
// janet_table_put at janet.c:33237:6 in janet.h
// janet_init at vm.c:1652:5 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_table_put at janet.c:33237:6 in janet.h
// janet_table_get at janet.c:33179:7 in janet.h
// janet_table_remove at janet.c:33222:7 in janet.h
// janet_nanbox_from_pointer at janet.c:37686:7 in janet.h
// janet_nanbox_to_pointer at janet.c:37680:7 in janet.h
// janet_table_rawget at janet.c:33212:7 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static Janet random_janet_value(const uint8_t *Data, size_t Size, size_t *Offset) {
    if (*Offset + sizeof(Janet) <= Size) {
        Janet value;
        memcpy(&value, Data + *Offset, sizeof(Janet));
        *Offset += sizeof(Janet);
        return value;
    }
    return (Janet){.u64 = 0}; // return a default value if out of bounds
}

static JanetTable *initialize_table(const uint8_t *Data, size_t Size, size_t *Offset) {
    JanetTable *table = janet_table(10);
    if (!table) return NULL;

    int32_t count = (Size - *Offset) / (2 * sizeof(JanetKV));
    for (int32_t i = 0; i < count; i++) {
        Janet key = random_janet_value(Data, Size, Offset);
        Janet value = random_janet_value(Data, Size, Offset);
        janet_table_put(table, key, value);
    }
    return table;
}

int LLVMFuzzerTestOneInput_346(const uint8_t *Data, size_t Size) {
    // Initialize Janet environment
    janet_init();

    size_t offset = 0;
    JanetTable *table = initialize_table(Data, Size, &offset);
    if (!table) {
        janet_deinit();
        return 0;
    }

    while (offset < Size) {
        Janet key = random_janet_value(Data, Size, &offset);
        Janet value = random_janet_value(Data, Size, &offset);

        // Test janet_table_put
        janet_table_put(table, key, value);

        // Test janet_table_get
        janet_table_get(table, key);

        // Test janet_table_remove
        janet_table_remove(table, key);

        // Test janet_wrap_table
        Janet wrapped_table = janet_wrap_table(table);

        // Test janet_unwrap_table
        JanetTable *unwrapped_table = janet_unwrap_table(wrapped_table);
        if (unwrapped_table) {
            // Test janet_table_rawget
            janet_table_rawget(unwrapped_table, key);
        }
    }

    // No manual free of table or its data as Janet handles memory management
    // Deinitialize Janet environment
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

        LLVMFuzzerTestOneInput_346(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    