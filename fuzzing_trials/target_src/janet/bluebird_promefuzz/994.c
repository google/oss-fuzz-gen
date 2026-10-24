#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

#define MAX_CAPACITY 1024

static JanetTable dummy_table;

int LLVMFuzzerTestOneInput_994(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) {
        return 0;
    }

    int32_t capacity = *((int32_t *)Data);
    capacity = capacity < 0 ? 0 : capacity % (MAX_CAPACITY + 1);

    janet_init();

    // Test janet_table_init
    janet_table_init(&dummy_table, capacity);

    // Test janet_table_init_raw
    janet_table_init_raw(&dummy_table, capacity);

    // Test janet_table_weakk
    JanetTable *weakk_table = janet_table_weakk(capacity);
    (void)weakk_table; // Suppress unused variable warning

    // Test janet_table_weakv
    JanetTable *weakv_table = janet_table_weakv(capacity);
    (void)weakv_table; // Suppress unused variable warning

    // Test janet_table_weakkv
    JanetTable *weakkv_table = janet_table_weakkv(capacity);
    (void)weakkv_table; // Suppress unused variable warning

    // Test janet_table
    JanetTable *new_table = janet_table(capacity);
    (void)new_table; // Suppress unused variable warning

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

    LLVMFuzzerTestOneInput_994(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
