#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"
#include <string.h>

int LLVMFuzzerTestOneInput_311(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Create a JanetTable
    JanetTable *table = janet_table(10);

    // Ensure the size is sufficient for creating strings
    if (size < 6) {
        janet_deinit();
        return 0;
    }

    // Use the data to create strings and an integer
    // Ensure strings are null-terminated and within bounds
    const char *key = (const char *)data;
    size_t key_len = strnlen(key, size);
    if (key_len >= size) {
        janet_deinit();
        return 0;
    }

    const char *doc = (const char *)(data + key_len + 1);
    size_t doc_len = strnlen(doc, size - key_len - 1);
    if (key_len + 1 + doc_len >= size) {
        janet_deinit();
        return 0;
    }

    const char *source = (const char *)(data + key_len + 1 + doc_len + 1);
    size_t source_len = strnlen(source, size - key_len - 1 - doc_len - 1);
    if (key_len + 1 + doc_len + 1 + source_len >= size) {
        janet_deinit();
        return 0;
    }

    int32_t flags = (int32_t)data[key_len + 1 + doc_len + 1 + source_len];

    // Create a Janet value
    Janet value = janet_wrap_integer((int32_t)data[key_len + 1 + doc_len + 1 + source_len + 1]);

    // Call the function-under-test
    janet_def_sm(table, key, value, doc, source, flags);

    // Clean up Janet runtime
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

    LLVMFuzzerTestOneInput_311(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
