// This fuzz driver is generated for library libucl, aiming to fuzz the following functions:
// ucl_object_fromstring at ucl_util.c:3100:1 in ucl.h
// ucl_object_fromstring at ucl_util.c:3100:1 in ucl.h
// ucl_array_append at ucl_util.c:3153:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_fromstring at ucl_util.c:3100:1 in ucl.h
// ucl_array_replace_index at ucl_util.c:3400:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_lookup_path at ucl_util.c:2931:1 in ucl.h
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
#include <stdio.h>
#include <string.h>

int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Convert input data to a null-terminated string
    char *input_string = (char *)malloc(Size + 1);
    if (!input_string) return 0;
    memcpy(input_string, Data, Size);
    input_string[Size] = '\0';

    // Create a UCL object from the input string
    ucl_object_t *obj1 = ucl_object_fromstring(input_string);
    if (obj1 == NULL) {
        free(input_string);
        return 0;
    }

    // Initialize an array object
    ucl_object_t *array = ucl_object_fromstring("[]");

    // Append the first object to the array
    if (!ucl_array_append(array, obj1)) {
        ucl_object_unref(obj1);
        ucl_object_unref(array);
        free(input_string);
        return 0;
    }

    // Replace index 0 in the array with a new object
    ucl_object_t *obj2 = ucl_object_fromstring(input_string);
    ucl_object_t *replaced = ucl_array_replace_index(array, obj2, 0);

    // Unref the replaced object if it exists
    if (replaced != NULL) {
        ucl_object_unref(replaced);
    }

    // Lookup a path in the array
    const ucl_object_t *lookup_result = ucl_object_lookup_path(array, "0");

    // Cleanup
    ucl_object_unref(array);
    free(input_string);

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

    LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
