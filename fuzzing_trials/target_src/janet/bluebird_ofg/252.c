#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "janet.h"

// Function signature for the function-under-test
void janet_var_sm(JanetTable *table, const char *key, Janet value, const char *doc, const char *source, int32_t flags);

// Fuzzing harness
int LLVMFuzzerTestOneInput_252(const uint8_t *data, size_t size) {
    // Initialize Janet
    janet_init();

    // Create a JanetTable
    JanetTable *table = janet_table(10);

    // Ensure we have enough data for the strings and integer
    if (size < 4) { // Adjusted to ensure we have enough space for null-terminators
        janet_deinit();
        return 0;
    }

    // Allocate buffers for strings and ensure they are null-terminated
    char key[256] = {0}; // Buffer for key
    char doc[256] = {0}; // Buffer for doc
    char source[256] = {0}; // Buffer for source

    // Copy data into buffers and ensure null-termination
    size_t key_len = size > 255 ? 255 : size;
    memcpy(key, data, key_len);
    key[key_len] = '\0';

    size_t doc_len = size > 254 ? 254 : size - 1;
    memcpy(doc, data + 1, doc_len);
    doc[doc_len] = '\0';

    size_t source_len = size > 253 ? 253 : size - 2;
    memcpy(source, data + 2, source_len);
    source[source_len] = '\0';

    int32_t flags = (int32_t)data[3];

    // Create a Janet value (for simplicity, we'll use a number)
    Janet value = janet_wrap_integer((int32_t)size);

    // Call the function-under-test
    janet_var_sm(table, key, value, doc, source, flags);

    // Clean up Janet
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

    LLVMFuzzerTestOneInput_252(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
