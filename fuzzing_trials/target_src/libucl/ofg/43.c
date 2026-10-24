#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_43(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the parameters
    if (size < 2) {
        return 0;
    }

    // Initialize UCL objects
    ucl_object_t *top = ucl_object_typed_new(UCL_OBJECT);
    ucl_object_t *obj = ucl_object_typed_new(UCL_OBJECT);

    // Use the first byte as a boolean value
    bool replace = data[0] % 2 == 0;

    // Use the remaining data as the key
    const char *key = (const char *)(data + 1);
    size_t key_len = size - 1;

    // Call the function-under-test
    bool result = ucl_object_insert_key(top, obj, key, key_len, replace);

    // Clean up UCL objects
    ucl_object_unref(top);
    ucl_object_unref(obj);

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

    LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
