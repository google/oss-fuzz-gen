#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"
#include <string.h>
#include <stdlib.h> // Include for malloc and free

int LLVMFuzzerTestOneInput_321(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for splitting into parts
    if (size < 4) {
        return 0;
    }

    // Initialize Janet
    janet_init();

    // Create a JanetTable
    JanetTable *table = janet_table(10);

    // Split the data into parts for each parameter
    const char *key = (const char *)data;
    size_t key_len = size / 2;
    const char *documentation = (const char *)(data + key_len);
    size_t doc_len = size - key_len;

    // Ensure strings are null-terminated
    char *key_copy = (char *)malloc(key_len + 1);
    char *doc_copy = (char *)malloc(doc_len + 1);
    if (!key_copy || !doc_copy) {
        free(key_copy);
        free(doc_copy);
        janet_deinit();
        return 0;
    }
    memcpy(key_copy, key, key_len);
    key_copy[key_len] = '\0';
    memcpy(doc_copy, documentation, doc_len);
    doc_copy[doc_len] = '\0';

    // Create a Janet value
    Janet value = janet_wrap_integer(42); // Example integer value

    // Call the function-under-test
    janet_var(table, key_copy, value, doc_copy);

    // Clean up
    free(key_copy);
    free(doc_copy);
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

    LLVMFuzzerTestOneInput_321(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
