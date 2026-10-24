#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_135(const uint8_t *data, size_t size) {
    // Declare and initialize ucl_object_t pointers
    ucl_object_t *obj1 = ucl_object_new();
    ucl_object_t *obj2 = ucl_object_new();

    // Ensure that the objects are not NULL
    if (obj1 == NULL || obj2 == NULL) {
        return 0;
    }

    // Use the data to initialize the objects
    ucl_object_t *parsed_obj1 = ucl_object_fromstring((const char *)data);
    ucl_object_t *parsed_obj2 = ucl_object_fromstring((const char *)data);

    if (parsed_obj1 != NULL) {
        ucl_object_insert_key(obj1, parsed_obj1, "key1", 4, false);
    }

    if (parsed_obj2 != NULL) {
        ucl_object_insert_key(obj2, parsed_obj2, "key2", 4, false);
    }

    // Call the function under test
    ucl_object_t *result = ucl_elt_append(obj1, obj2);

    // Cleanup
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

    LLVMFuzzerTestOneInput_135(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
