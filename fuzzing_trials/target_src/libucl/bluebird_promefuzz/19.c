#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "ucl.h"

static ucl_object_t* create_random_ucl_object(const uint8_t *Data, size_t Size) {
    ucl_object_t *obj = (ucl_object_t *)malloc(sizeof(ucl_object_t));
    if (obj == NULL) {
        return NULL;
    }
    
    memset(obj, 0, sizeof(ucl_object_t)); // Ensure all fields are zero-initialized

    // Initialize the object with random data based on input
    if (Size >= sizeof(int64_t)) {
        obj->value.iv = *(int64_t *)Data;
        obj->type = UCL_INT;
    } else {
        obj->value.dv = 0.0;
        obj->type = UCL_FLOAT;
    }
    
    obj->ref = 1;
    return obj;
}

int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int64_t) * 2) {
        return 0; // Insufficient data for meaningful fuzzing
    }

    ucl_object_t *array = create_random_ucl_object(Data, Size);
    ucl_object_t *element = create_random_ucl_object(Data + sizeof(int64_t), Size - sizeof(int64_t));
    
    if (array == NULL || element == NULL) {
        free(array);
        free(element);
        return 0;
    }

    // Initialize the array as an actual array type
    array->type = UCL_ARRAY;
    array->value.av = NULL; // Assume this is necessary for libucl's internal handling

    // Fuzz ucl_array_append
    bool append_result = ucl_array_append(array, element);

    // Fuzz ucl_array_delete
    ucl_object_t *deleted_element = ucl_array_delete(array, element);

    // Fuzz ucl_object_todouble
    double result = ucl_object_todouble(element);

    // Cleanup
    if (deleted_element && deleted_element != element) {
        ucl_object_unref(deleted_element);
    }
    ucl_object_unref(element);
    ucl_object_unref(array);

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

    LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
