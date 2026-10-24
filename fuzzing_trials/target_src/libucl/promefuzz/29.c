// This fuzz driver is generated for library libucl, aiming to fuzz the following functions:
// ucl_object_typed_new at ucl_util.c:2998:1 in ucl.h
// ucl_object_typed_new at ucl_util.c:2998:1 in ucl.h
// ucl_comments_find at ucl_util.c:3947:1 in ucl.h
// ucl_object_typed_new at ucl_util.c:2998:1 in ucl.h
// ucl_object_fromstring at ucl_util.c:3100:1 in ucl.h
// ucl_elt_append at ucl_util.c:3419:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare dummy data for fuzzing
    const char *dummy_string = "dummy";
    ucl_object_t *comments_obj = ucl_object_typed_new(UCL_OBJECT);
    ucl_object_t *search_obj = ucl_object_typed_new(UCL_OBJECT);

    // Attempt to find comments
    const ucl_object_t *comment = ucl_comments_find(comments_obj, search_obj);
    (void)comment;

    // Create new UCL object from data
    ucl_object_t *new_obj = ucl_object_typed_new((ucl_type_t)(Data[0] % (UCL_NULL + 1)));

    // Create UCL object from string
    ucl_object_t *str_obj = ucl_object_fromstring(dummy_string);

    // Append the string object to the new object
    ucl_object_t *result_obj = ucl_elt_append(new_obj, str_obj);
    (void)result_obj;

    // Cleanup
    ucl_object_unref(comments_obj);
    ucl_object_unref(search_obj);
    ucl_object_unref(new_obj);
    // Do not unref str_obj separately as it's now part of new_obj or result_obj

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

    LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
