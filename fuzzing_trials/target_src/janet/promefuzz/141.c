// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_parser_init at parse.c:784:6 in janet.h
// janet_parser_deinit at parse.c:804:6 in janet.h
// janet_smalloc at gc.c:706:7 in janet.h
// janet_sfree at gc.c:759:6 in janet.h
// janet_table_init at janet.c:33101:13 in janet.h
// janet_table_deinit at janet.c:33111:6 in janet.h
// janet_buffer_init at buffer.c:54:14 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void fuzz_janet_parser_deinit(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetParser)) return;
    JanetParser parser;
    janet_parser_init(&parser); // Properly initialize the parser
    // Use Data to simulate some operations if needed
    janet_parser_deinit(&parser);
}

static void fuzz_janet_sfree(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(void *)) return;
    // Ensure the memory pointer is valid and allocated by Janet's memory management
    void *mem = janet_smalloc(Size);
    if (mem) {
        memcpy(mem, Data, Size);
        janet_sfree(mem);
    }
}

static void fuzz_janet_table_deinit(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetTable)) return;
    JanetTable table;
    janet_table_init(&table, 0); // Properly initialize the table
    // Use Data to simulate some operations if needed
    janet_table_deinit(&table);
}

static void fuzz_janet_buffer_deinit(const uint8_t *Data, size_t Size) {
    JanetBuffer buffer;
    janet_buffer_init(&buffer, 0); // Properly initialize the buffer
    // Use Data to simulate some operations if needed
    janet_buffer_deinit(&buffer);
}

static void fuzz_janet_deinit() {
    // Ensure janet_deinit is called only once and after manual deallocations
    static int deinit_called = 0;
    if (!deinit_called) {
        janet_deinit();
        deinit_called = 1;
    }
}

int LLVMFuzzerTestOneInput_141(const uint8_t *Data, size_t Size) {
    fuzz_janet_parser_deinit(Data, Size);
    fuzz_janet_sfree(Data, Size);
    fuzz_janet_table_deinit(Data, Size);
    fuzz_janet_buffer_deinit(Data, Size);
    fuzz_janet_deinit();
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

        LLVMFuzzerTestOneInput_141(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    