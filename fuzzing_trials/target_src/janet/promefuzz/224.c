// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_opttable at janet.c:4539:1 in janet.h
// janet_table_init_raw at janet.c:33106:13 in janet.h
// janet_table_merge_table at janet.c:33313:6 in janet.h
// janet_dostring at run.c:139:5 in janet.h
// janet_table_weakv at janet.c:33131:13 in janet.h
// janet_gettable at janet.c:4514:1 in janet.h
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

#define MAX_CAPACITY 1024
#define DUMMY_FILE "./dummy_file"

static void prepare_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen(DUMMY_FILE, "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_224(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t) * 4) return 0;

    // Initialize Janet VM
    janet_init();

    // Prepare dummy file
    prepare_dummy_file(Data, Size);

    // Extract parameters from Data
    int32_t argc = ((int32_t *)Data)[0];
    int32_t n = ((int32_t *)Data)[1];
    int32_t dflt_len = ((int32_t *)Data)[2];
    int32_t capacity = ((int32_t *)Data)[3];

    // Ensure capacity is within reasonable range
    if (capacity < 0 || capacity > MAX_CAPACITY) {
        capacity = MAX_CAPACITY;
    }

    // Prepare Janet array from remaining data
    const Janet *argv = (const Janet *)(Data + sizeof(int32_t) * 4);

    // Ensure argc is within bounds of available Janet data
    if (argc < 0 || argc > (Size - sizeof(int32_t) * 4) / sizeof(Janet)) {
        argc = (Size - sizeof(int32_t) * 4) / sizeof(Janet);
    }

    // Fuzz janet_opttable
    JanetTable *opt_table = janet_opttable(argv, argc, n, dflt_len);

    // Fuzz janet_table_init_raw
    JanetTable table;
    JanetTable *initialized_table = janet_table_init_raw(&table, capacity);

    // Fuzz janet_table_merge_table
    if (opt_table) {
        janet_table_merge_table(initialized_table, opt_table);
    }

    // Fuzz janet_dostring
    Janet result;
    janet_dostring(initialized_table, "print(\"Hello, Janet!\")", DUMMY_FILE, &result);

    // Fuzz janet_table_weakv
    JanetTable *weak_table = janet_table_weakv(capacity);

    // Fuzz janet_gettable
    if (argc > 0) {
        JanetTable *retrieved_table = janet_gettable(argv, 0);
    }

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

        LLVMFuzzerTestOneInput_224(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    