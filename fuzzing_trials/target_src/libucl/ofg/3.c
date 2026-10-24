#include <stdint.h>
#include <stdbool.h>
#include <ucl.h>

int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    // Initialize ucl_object_t pointers
    ucl_object_t *obj1 = ucl_object_new();
    ucl_object_t *obj2 = ucl_object_new();

    // Ensure the objects are not NULL
    if (obj1 == NULL || obj2 == NULL) {
        return 0;
    }

    // Parse the input data into obj1
    // Adjust the function call to use the correct number of arguments
    if (!ucl_object_fromstring_common((const char *)data, size, UCL_STRING_RAW)) {
        ucl_object_unref(obj1);
        ucl_object_unref(obj2);
        return 0;
    }

    // Create a boolean value for the merge option
    bool merge_option = true; // You can try both true and false

    // Call the function under test
    bool result = ucl_array_merge(obj1, obj2, merge_option);

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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
