#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "janet.h"

#define MAX_CAPACITY 1024

static JanetTable *initialize_table(JanetTable *table, int32_t capacity, int choice) {
    switch (choice) {
        case 0:
            return janet_table_init(table, capacity);
        case 1:
            return janet_table_init_raw(table, capacity);
        default:
            return NULL;
    }
}

int LLVMFuzzerTestOneInput_992(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    janet_init();

    int32_t capacity = Data[0] % MAX_CAPACITY;

    JanetTable table;
    initialize_table(&table, capacity, Data[0] % 2);

    janet_table_weakk(capacity);
    janet_table_weakv(capacity);
    janet_table_weakkv(capacity);
    janet_table(capacity);

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

    LLVMFuzzerTestOneInput_992(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
