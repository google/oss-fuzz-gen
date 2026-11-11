#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "ucl.h"

// Define an enumeration type for the sort flags
typedef enum {
    UCL_OBJECT_KEYS_SORT_FLAGS_NONE = 0,
    UCL_OBJECT_KEYS_SORT_FLAGS_CASE_INSENSITIVE = 1,
    UCL_OBJECT_KEYS_SORT_FLAGS_REVERSE = 2
} ucl_object_keys_sort_flags;

int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    ucl_object_t *ucl_obj;
    ucl_object_keys_sort_flags sort_flags;

    // Initialize a UCL object
    ucl_obj = ucl_object_typed_new(UCL_OBJECT);

    // Ensure the UCL object is not NULL
    if (ucl_obj == NULL) {
        return 0;
    }

    // Populate the UCL object with some data
    // This is a simple example, you can add more complex data if needed
    ucl_object_insert_key(ucl_obj, ucl_object_fromstring("value1"), "key1", 0, false);
    ucl_object_insert_key(ucl_obj, ucl_object_fromstring("value2"), "key2", 0, false);

    // Set the sort flags based on the input data
    if (size > 0) {
        sort_flags = (ucl_object_keys_sort_flags)(data[0] % 3); // 3 possible flags
    } else {
        sort_flags = UCL_OBJECT_KEYS_SORT_FLAGS_NONE;
    }

    // Call the function-under-test
    ucl_object_sort_keys(ucl_obj, sort_flags);

    // Clean up
    ucl_object_unref(ucl_obj);

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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
