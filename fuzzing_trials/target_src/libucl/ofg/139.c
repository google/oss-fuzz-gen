#include <stdint.h>
#include <stdlib.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
    // Initialize ucl_object_t pointers
    ucl_object_t *array = ucl_object_typed_new(UCL_ARRAY);
    ucl_object_t *element = ucl_object_fromstring("test_element");

    // Ensure data is not empty before using it
    if (size > 0) {
        // Use the data to create a new UCL object
        ucl_object_t *data_object = ucl_object_fromstring((const char *)data);

        // Prepend the data object to the array
        ucl_array_prepend(array, data_object);

        // Clean up the data object
        ucl_object_unref(data_object);
    }

    // Prepend the element to the array
    ucl_array_prepend(array, element);

    // Clean up
    ucl_object_unref(array);
    ucl_object_unref(element);

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

    LLVMFuzzerTestOneInput_139(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
