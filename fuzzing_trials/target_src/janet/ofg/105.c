#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h" // Assuming janet.h provides the definition for JanetTable

extern void janet_env_lookup_into(JanetTable *env, JanetTable *dest, const char *key, int flags);

int LLVMFuzzerTestOneInput_105(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create a null-terminated string
    if (size < 1) return 0;

    // Create and initialize JanetTable structures
    JanetTable env;
    JanetTable dest;
    memset(&env, 0, sizeof(JanetTable));
    memset(&dest, 0, sizeof(JanetTable));

    // Initialize the env table with some data
    // Assuming janet_table_put is a function to add data to a JanetTable
    // and janet_wrap_string is a function to wrap a C string in a Janet value
    if (size > 1) {
        char *sample_key = "sample";
        char *sample_value = "value";
        janet_table_put(&env, janet_wrap_string(sample_key), janet_wrap_string(sample_value));
    }

    // Copy data to a null-terminated string for the key
    char *key = (char *)malloc(size + 1);
    if (!key) return 0;
    memcpy(key, data, size);
    key[size] = '\0';

    // Use a fixed integer for flags (try different values for thorough testing)
    int flags = 0;

    // Call the function-under-test
    janet_env_lookup_into(&env, &dest, key, flags);

    // Free allocated memory
    free(key);

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

    LLVMFuzzerTestOneInput_105(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
