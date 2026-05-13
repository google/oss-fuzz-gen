#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    // Declare and initialize ucl_object_t pointers
    ucl_object_t *obj1 = ucl_object_new();
    ucl_object_t *obj2 = ucl_object_new();
    ucl_object_t *obj3 = ucl_object_new();

    // Ensure the objects are initialized with some data
    if (size > 0) {
        // Use the provided data to initialize the objects
        ucl_object_fromstring_common((const char *)data, size, 0);
        ucl_object_fromstring_common((const char *)data, size, 0);
        ucl_object_fromstring_common((const char *)data, size, 0);
    } else {
        // Default initialization if size is 0
        ucl_object_fromstring_common("default1", 8, 0);
        ucl_object_fromstring_common("default2", 8, 0);
        ucl_object_fromstring_common("default3", 8, 0);
    }

    // Call the function-under-test
    bool result = ucl_comments_move(obj1, obj2, obj3);

    // Clean up
    ucl_object_unref(obj1);
    ucl_object_unref(obj2);
    ucl_object_unref(obj3);

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

    LLVMFuzzerTestOneInput_30(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
