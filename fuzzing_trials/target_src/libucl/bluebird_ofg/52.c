#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "ucl.h"

// Ensure the necessary macro is defined for using certain UCL functions
#define UCL_EMIT_JSON_COMPACT

int LLVMFuzzerTestOneInput_52(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for a key
    if (size < 2) {
        return 0;
    }

    // Initialize ucl_object_t
    ucl_object_t *obj = ucl_object_typed_new(UCL_OBJECT);

    // Create a key from the input data
    size_t key_length = size / 2;
    char *key = (char *)malloc(key_length + 1);
    if (key == NULL) {
        ucl_object_unref(obj);
        return 0;
    }
    memcpy(key, data, key_length);
    key[key_length] = '\0';

    // Use the remaining data as a value
    ucl_object_t *value = ucl_object_fromstring_common((const char *)(data + key_length), size - key_length, 0);
    if (value != NULL) {
        ucl_object_insert_key(obj, value, key, key_length, false);
    }

    // Call the function-under-test
    bool result = ucl_object_delete_keyl(obj, key, key_length);

    // Clean up
    ucl_object_unref(obj);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_52(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
