#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "janet.h"

#define MAX_CAPACITY 1024

static int32_t get_capacity(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) {
        return 0;
    }
    int32_t capacity;
    memcpy(&capacity, Data, sizeof(int32_t));
    return (capacity < 0 || capacity > MAX_CAPACITY) ? 0 : capacity;
}

int LLVMFuzzerTestOneInput_988(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) {
        return 0;
    }

    int32_t capacity = get_capacity(Data, Size);

    janet_init();

    JanetTable table;
    JanetTable *initialized_table = janet_table_init(&table, capacity);
    if (initialized_table == NULL) {
        janet_deinit();
        return 0;
    }

    initialized_table = janet_table_init_raw(&table, capacity);
    if (initialized_table == NULL) {
        janet_deinit();
        return 0;
    }

    JanetTable *weakv_table = janet_table_weakv(capacity);
    if (weakv_table == NULL) {
        janet_deinit();
        return 0;
    }
    janet_gcroot(janet_wrap_table(weakv_table));

    JanetTable *weakk_table = janet_table_weakk(capacity);
    if (weakk_table == NULL) {
        janet_deinit();
        return 0;
    }
    janet_gcroot(janet_wrap_table(weakk_table));

    JanetTable *weakkv_table = janet_table_weakkv(capacity);
    if (weakkv_table == NULL) {
        janet_deinit();
        return 0;
    }
    janet_gcroot(janet_wrap_table(weakkv_table));

    JanetTable *new_table = janet_table(capacity);
    if (new_table == NULL) {
        janet_deinit();
        return 0;
    }
    janet_gcroot(janet_wrap_table(new_table));

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

    LLVMFuzzerTestOneInput_988(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
