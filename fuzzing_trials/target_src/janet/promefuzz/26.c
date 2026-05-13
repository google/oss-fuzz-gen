// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_sfree at gc.c:759:6 in janet.h
// janet_table_deinit at janet.c:33111:6 in janet.h
// janet_buffer_deinit at buffer.c:74:6 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void fuzz_janet_sfree(const uint8_t *Data, size_t Size) {
    // Avoid using janet_sfree directly on arbitrary data
    // Instead, ensure memory is allocated in a way that janet_sfree expects
    if (Size < sizeof(void *)) return;
    void *mem = malloc(Size);
    if (mem) {
        memcpy(mem, Data, Size);
        // Simulate proper allocation and management
        janet_sfree(NULL); // Safe to call on NULL
        free(mem); // Free manually allocated memory
    }
}

static void fuzz_janet_table_deinit(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetTable)) return;
    JanetTable *table = (JanetTable *)malloc(sizeof(JanetTable));
    if (table) {
        memcpy(table, Data, sizeof(JanetTable));
        table->data = NULL; // Ensure data is initialized to avoid invalid access
        janet_table_deinit(table);
        free(table);
    }
}

static void fuzz_janet_buffer_deinit(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetBuffer)) return;
    JanetBuffer *buffer = (JanetBuffer *)malloc(sizeof(JanetBuffer));
    if (buffer) {
        memcpy(buffer, Data, sizeof(JanetBuffer));
        buffer->data = malloc(buffer->capacity); // Allocate buffer data
        if (buffer->data) {
            memcpy(buffer->data, Data, buffer->capacity < Size ? buffer->capacity : Size);
        } else {
            buffer->capacity = 0; // Ensure capacity is zero if allocation failed
        }
        janet_buffer_deinit(buffer);
        free(buffer->data);
        free(buffer);
    }
}

static void fuzz_janet_free(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(void *)) return;
    void *mem = malloc(Size);
    if (mem) {
        memcpy(mem, Data, Size);
        janet_free(mem);
    } else {
        janet_free(NULL);
    }
}

static void fuzz_janet_deinit(void) {
    janet_deinit();
}

int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    fuzz_janet_sfree(Data, Size);
    fuzz_janet_table_deinit(Data, Size);
    fuzz_janet_buffer_deinit(Data, Size);
    fuzz_janet_free(Data, Size);
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

        LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    