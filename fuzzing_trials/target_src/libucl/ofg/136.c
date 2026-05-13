#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_136(const uint8_t *data, size_t size) {
    ucl_object_t *obj1 = ucl_object_new();
    ucl_object_t *obj2 = ucl_object_new();

    // Ensure that the objects are not NULL
    if (obj1 == NULL || obj2 == NULL) {
        return 0;
    }

    // Use the provided data to set some properties in the objects
    ucl_object_insert_key(obj1, ucl_object_fromstring((const char *)data), "key1", 0, false);
    ucl_object_insert_key(obj2, ucl_object_fromstring((const char *)data), "key2", 0, false);

    // Call the function-under-test
    ucl_object_t *result = ucl_elt_append(obj1, obj2);

    // Clean up
    ucl_object_unref(obj1);
    ucl_object_unref(obj2);
    if (result != obj1) {
        ucl_object_unref(result);
    }

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_136(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
