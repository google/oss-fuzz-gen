// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_table_init at janet.c:33101:13 in janet.h
// janet_table_init_raw at janet.c:33106:13 in janet.h
// janet_table_weakk at janet.c:33126:13 in janet.h
// janet_table_weakv at janet.c:33131:13 in janet.h
// janet_table_weakkv at janet.c:33136:13 in janet.h
// janet_table at janet.c:33121:13 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

#define MAX_CAPACITY 1024

static int32_t get_int32_from_data(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) {
        return 0;
    }
    int32_t value;
    memcpy(&value, Data, sizeof(int32_t));
    return value;
}

int LLVMFuzzerTestOneInput_233(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) {
        return 0;
    }

    janet_init();

    int32_t capacity = get_int32_from_data(Data, Size);
    if (capacity < 0 || capacity > MAX_CAPACITY) {
        capacity = MAX_CAPACITY;
    }

    JanetTable table;
    janet_table_init(&table, capacity);
    janet_table_init_raw(&table, capacity);

    JanetTable *weakk_table = janet_table_weakk(capacity);
    if (weakk_table) {
        // Perform operations on weakk_table if needed
    }

    JanetTable *weakv_table = janet_table_weakv(capacity);
    if (weakv_table) {
        // Perform operations on weakv_table if needed
    }

    JanetTable *weakkv_table = janet_table_weakkv(capacity);
    if (weakkv_table) {
        // Perform operations on weakkv_table if needed
    }

    JanetTable *new_table = janet_table(capacity);
    if (new_table) {
        // Perform operations on new_table if needed
    }

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

        LLVMFuzzerTestOneInput_233(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    