#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(double)) {
        return 0;
    }

    // Extract a double value from the input data
    double dv;
    memcpy(&dv, Data, sizeof(double));

    // Create a UCL object from the double
    ucl_object_t *double_obj = ucl_object_fromdouble(dv);
    if (double_obj == NULL) {
        return 0;
    }

    // Create a UCL array object
    ucl_object_t *array_obj = ucl_object_fromdouble(0.0); // Dummy initialization
    if (array_obj == NULL) {
        ucl_object_unref(double_obj);
        return 0;
    }
    array_obj->type = UCL_ARRAY;
    array_obj->value.av = NULL;

    // Prepend the double object to the array
    bool prepend_result = ucl_array_prepend(array_obj, double_obj);
    if (!prepend_result) {
        ucl_object_unref(double_obj);
        ucl_object_unref(array_obj);
        return 0;
    }

    // Pop the first element from the array
    ucl_object_t *popped_obj = ucl_array_pop_first(array_obj);
    if (popped_obj != NULL) {
        ucl_object_unref(popped_obj);
    }

    // Clean up
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

    LLVMFuzzerTestOneInput_9(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
