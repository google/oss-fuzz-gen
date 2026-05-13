#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

// Declaration of the janet_table_deinit function
extern void janet_table_deinit(JanetTable *);

// External function declaration for janet_table
extern JanetTable *janet_table(int32_t);

int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    int32_t capacity;

    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Use the first 4 bytes of data to set the capacity
    capacity = *(int32_t *)data;

    // Ensure capacity is within a reasonable range
    if (capacity < 0 || capacity > 10000) {
        return 0;
    }

    // Call the function-under-test
    JanetTable *table = janet_table(capacity);

    // Clean up if necessary
    if (table != NULL) {
        janet_table_deinit(table);
    }

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

    LLVMFuzzerTestOneInput_35(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
