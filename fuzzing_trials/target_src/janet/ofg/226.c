#include <stdint.h>
#include <stddef.h>
#include <janet.h>

extern void janet_var(JanetTable *table, const char *key, Janet value, const char *doc);

int LLVMFuzzerTestOneInput_226(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract meaningful inputs
    if (size < 2) {
        return 0;
    }

    // Initialize Janet environment
    janet_init();

    // Create a JanetTable
    JanetTable *table = janet_table(10);

    // Extract a key from the input data
    size_t key_len = size / 2;
    char *key = (char *)malloc(key_len + 1);
    if (!key) {
        janet_deinit();
        return 0;
    }
    memcpy(key, data, key_len);
    key[key_len] = '\0';

    // Extract a value from the input data
    Janet value = janet_wrap_integer((int32_t)data[key_len]);

    // Extract a documentation string from the input data
    size_t doc_len = size - key_len - 1;
    char *doc = (char *)malloc(doc_len + 1);
    if (!doc) {
        free(key);
        janet_deinit();
        return 0;
    }
    memcpy(doc, data + key_len + 1, doc_len);
    doc[doc_len] = '\0';

    // Call the function-under-test
    janet_var(table, key, value, doc);

    // Clean up
    free(key);
    free(doc);
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

    LLVMFuzzerTestOneInput_226(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
