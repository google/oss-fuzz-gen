// This fuzz driver is generated for library libucl, aiming to fuzz the following functions:
// ucl_object_new at ucl_util.c:2992:1 in ucl.h
// ucl_object_fromstring at ucl_util.c:3100:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_array_index_of at ucl_util.c:3377:1 in ucl.h
// ucl_object_copy at ucl_util.c:3714:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_fromstring at ucl_util.c:3100:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_array_prepend at ucl_util.c:3185:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ucl.h>
#include <stdbool.h>

static ucl_object_t *create_empty_ucl_array() {
    ucl_object_t *array = ucl_object_new();
    if (array) {
        array->type = UCL_ARRAY;
    }
    return array;
}

static ucl_object_t *create_dummy_ucl_object() {
    return ucl_object_fromstring("dummy");
}

int LLVMFuzzerTestOneInput_7(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    // Create an empty UCL array
    ucl_object_t *ucl_array = create_empty_ucl_array();
    if (!ucl_array) {
        return 0;
    }

    // Create a dummy UCL object
    ucl_object_t *ucl_object = create_dummy_ucl_object();
    if (!ucl_object) {
        ucl_object_unref(ucl_array);
        return 0;
    }

    // ucl_array_index_of
    unsigned int index = ucl_array_index_of(ucl_array, ucl_object);

    // ucl_object_copy
    ucl_object_t *copied_object = ucl_object_copy(ucl_object);
    if (!copied_object) {
        ucl_object_unref(ucl_array);
        ucl_object_unref(ucl_object);
        return 0;
    }

    // ucl_object_fromstring
    char *str = (char *)malloc(Size + 1);
    if (!str) {
        ucl_object_unref(ucl_array);
        ucl_object_unref(ucl_object);
        ucl_object_unref(copied_object);
        return 0;
    }
    memcpy(str, Data, Size);
    str[Size] = '\0';
    ucl_object_t *from_string_object = ucl_object_fromstring(str);
    free(str);
    if (!from_string_object) {
        ucl_object_unref(ucl_array);
        ucl_object_unref(ucl_object);
        ucl_object_unref(copied_object);
        return 0;
    }

    // ucl_array_prepend
    bool prepended = ucl_array_prepend(ucl_array, from_string_object);

    // Cleanup
    ucl_object_unref(ucl_array);
    ucl_object_unref(ucl_object);
    ucl_object_unref(copied_object);
    if (!prepended) {
        ucl_object_unref(from_string_object);
    }

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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
