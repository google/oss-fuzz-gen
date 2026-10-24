// This fuzz driver is generated for library libucl, aiming to fuzz the following functions:
// ucl_object_fromstring at ucl_util.c:3100:1 in ucl.h
// ucl_object_fromstring at ucl_util.c:3100:1 in ucl.h
// ucl_array_prepend at ucl_util.c:3185:6 in ucl.h
// ucl_object_type at ucl_util.c:3090:1 in ucl.h
// ucl_object_array_sort at ucl_util.c:3821:6 in ucl.h
// ucl_object_fromdouble at ucl_util.c:3126:1 in ucl.h
// ucl_array_prepend at ucl_util.c:3185:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ucl.h>

static int cmp_func(const ucl_object_t **o1, const ucl_object_t **o2) {
    // A simple comparison function for sorting
    return 0; // No-op for fuzzing purposes
}

int LLVMFuzzerTestOneInput_24(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Convert input data to a null-terminated string
    char *inputStr = (char *)malloc(Size + 1);
    if (inputStr == NULL) return 0; // Handle malloc failure
    memcpy(inputStr, Data, Size);
    inputStr[Size] = '\0';

    // Create an array object
    ucl_object_t *array = ucl_object_fromstring("[]");
    if (array == NULL) {
        free(inputStr);
        return 0;
    }

    // Create UCL objects from input string and prepend them to the array
    for (int i = 0; i < 4; i++) {
        ucl_object_t *obj = ucl_object_fromstring(inputStr);
        if (obj != NULL) {
            ucl_array_prepend(array, obj);
        }
    }

    // Sort the array
    if (ucl_object_type(array) == UCL_ARRAY) {
        ucl_object_array_sort(array, cmp_func);
    }

    // Create a UCL object from a double
    ucl_object_t *double_obj = ucl_object_fromdouble(3.14159);
    if (double_obj != NULL) {
        ucl_array_prepend(array, double_obj);
    }

    // Cleanup
    ucl_object_unref(array);
    free(inputStr);

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

    LLVMFuzzerTestOneInput_24(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
