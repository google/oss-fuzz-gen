#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_117(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract meaningful inputs
    if (size < 2) {
        return 0;
    }

    // Initialize ucl objects
    ucl_object_t *obj1 = ucl_object_typed_new(UCL_OBJECT);
    ucl_object_t *obj2 = ucl_object_typed_new(UCL_OBJECT);

    // Use the first byte of data to determine the boolean value
    bool replace = data[0] % 2 == 0;

    // Use the rest of the data as the key
    const char *key = (const char *)(data + 1);
    size_t key_len = size - 1;

    // Call the function-under-test
    ucl_object_replace_key(obj1, obj2, key, key_len, replace);

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

    LLVMFuzzerTestOneInput_117(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
