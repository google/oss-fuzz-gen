#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Assuming JanetTable is a defined structure in the Janet library
typedef struct {
    // Dummy representation of JanetTable
    int dummy;
} JanetTable;

// Dummy function to simulate janet_env_lookup_into_104
void janet_env_lookup_into_104(JanetTable *table1, JanetTable *table2, const char *key, int flag) {
    // Simulate some processing
    printf("janet_env_lookup_into_104 called with key: %s and flag: %d\n", key, flag);
}

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_104(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to process
    }

    // Initialize JanetTable structures
    JanetTable table1 = {0};
    JanetTable table2 = {0};

    // Extract a key string from the input data
    size_t key_length = size < 256 ? size : 255; // Limit key length to 255
    char key[256];
    memcpy(key, data, key_length);
    key[key_length] = '\0'; // Null-terminate the key

    // Extract an integer flag from the input data
    int flag = (int)data[0]; // Use the first byte as the flag

    // Call the function-under-test
    janet_env_lookup_into_104(&table1, &table2, key, flag);

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_104(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
