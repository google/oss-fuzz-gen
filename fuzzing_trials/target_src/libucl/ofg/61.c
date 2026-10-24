#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_61(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for a key
    if (size < 1) {
        return 0;
    }

    // Initialize two ucl_object_t objects
    ucl_object_t *obj1 = ucl_object_new();
    ucl_object_t *obj2 = ucl_object_new();

    // Create a key from the input data
    const char *key = (const char *)data;

    // Use a portion of the data as the key length
    size_t key_len = size > 1 ? size - 1 : 1;

    // Use a boolean value from the input data
    bool merge = data[0] % 2 == 0;

    // Call the function under test
    ucl_object_insert_key_merged(obj1, obj2, key, key_len, merge);

    // Clean up
    ucl_object_unref(obj1);
    ucl_object_unref(obj2);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_61(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
