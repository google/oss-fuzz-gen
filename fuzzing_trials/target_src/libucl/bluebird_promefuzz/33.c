#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ucl.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static ucl_object_t *create_dummy_ucl_object(const uint8_t *Data, size_t Size) {
    ucl_object_t *obj = malloc(sizeof(ucl_object_t));
    if (!obj) return NULL;

    obj->type = UCL_ARRAY;
    obj->value.av = NULL; // Set to NULL as we do not have a valid array
    obj->len = 0; // Set length to 0 for safety
    return obj;
}

int LLVMFuzzerTestOneInput_33(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    ucl_object_t *ucl_obj = create_dummy_ucl_object(Data, Size);
    if (!ucl_obj) return 0;

    // 1. ucl_array_size
    unsigned int array_size = ucl_array_size(ucl_obj);

    // 2. ucl_object_iterate_with_error
    ucl_object_iter_t iter = NULL;
    int error = 0;
    const ucl_object_t *cur = ucl_object_iterate_with_error(ucl_obj, &iter, true, &error);

    // 3. ucl_object_tolstring
    size_t tlen = 0;
    const char *string_rep = ucl_object_tolstring(cur, &tlen);

    // 4. ucl_object_iterate_end
    ucl_object_iterate_end(ucl_obj, &iter);

    // 5. ucl_object_unref
    ucl_object_unref(ucl_obj);

    // 6. ucl_object_iterate_end (again)
    ucl_object_iterate_end(cur, &iter);

    // 7. ucl_object_unref (again)
    ucl_object_unref((ucl_object_t *)cur);

    // Clean up
    free(ucl_obj);

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

    LLVMFuzzerTestOneInput_33(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
