#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ucl.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    // Initialize ucl_object_t pointers
    ucl_object_t *top = ucl_object_typed_new(UCL_OBJECT);
    ucl_object_t *elt = ucl_object_typed_new(UCL_OBJECT);

    // Ensure data is not empty
    if (size == 0) {
        ucl_object_unref(top);
        ucl_object_unref(elt);
        return 0;
    }

    // Use the data as a key, ensuring it is null-terminated
    char *key = (char *)malloc(size + 1);
    if (key == NULL) {
        ucl_object_unref(top);
        ucl_object_unref(elt);
        return 0;
    }
    memcpy(key, data, size);
    key[size] = '\0';

    // Call the function-under-test
    bool result = ucl_object_insert_key_merged(top, elt, key, size, true);

    // Clean up
    ucl_object_unref(top);
    ucl_object_unref(elt);
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

    LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
