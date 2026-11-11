// This fuzz driver is generated for library libucl, aiming to fuzz the following functions:
// ucl_object_fromdouble at ucl_util.c:3126:1 in ucl.h
// ucl_object_fromdouble at ucl_util.c:3126:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_array_append at ucl_util.c:3153:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_array_pop_last at ucl_util.c:3305:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_todouble at ucl_util.c:3468:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ucl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_25(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) {
        return 0;
    }

    // Extract a double from the input data
    double dv;
    memcpy(&dv, Data, sizeof(double));

    // Create a UCL object from a double
    ucl_object_t *obj = ucl_object_fromdouble(dv);
    if (obj == NULL) {
        return 0;
    }

    // Create an array object
    ucl_object_t *array_obj = ucl_object_fromdouble(0.0); // Dummy initialization
    if (array_obj == NULL) {
        ucl_object_unref(obj);
        return 0;
    }

    // Append the object to the array
    bool append_result = ucl_array_append(array_obj, obj);
    if (!append_result) {
        ucl_object_unref(obj);
        ucl_object_unref(array_obj);
        return 0;
    }

    // Pop the last element from the array
    ucl_object_t *popped_obj = ucl_array_pop_last(array_obj);
    if (popped_obj == NULL) {
        ucl_object_unref(array_obj);
        return 0;
    }

    // Convert the popped object to a double
    double result = ucl_object_todouble(popped_obj);

    // Clean up
    ucl_object_unref(popped_obj);
    ucl_object_unref(array_obj);

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

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
