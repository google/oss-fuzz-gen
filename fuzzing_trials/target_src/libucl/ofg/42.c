#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_42(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    ucl_object_t *top = ucl_object_typed_new(UCL_OBJECT);
    ucl_object_t *obj = ucl_object_typed_new(UCL_OBJECT);
    const char *key = "fuzz_key";
    size_t keylen = 8; // Length of "fuzz_key"
    bool replace = true;

    // Ensure the data is not empty
    if (size > 0) {
        // Create a UCL object from the input data
        ucl_object_t *data_obj = ucl_object_fromstring((const char *)data);

        // Insert the data object into the top object with the specified key
        ucl_object_insert_key(top, data_obj, key, keylen, replace);
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
