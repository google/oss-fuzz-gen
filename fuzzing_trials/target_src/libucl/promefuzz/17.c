// This fuzz driver is generated for library libucl, aiming to fuzz the following functions:
// ucl_object_fromstring_common at ucl_util.c:2225:1 in ucl.h
// ucl_array_append at ucl_util.c:3153:6 in ucl.h
// ucl_array_size at ucl_util.c:3345:1 in ucl.h
// ucl_array_find_index at ucl_util.c:3361:1 in ucl.h
// ucl_array_size at ucl_util.c:3345:1 in ucl.h
// ucl_object_tolstring at ucl_util.c:3588:1 in ucl.h
// ucl_array_head at ucl_util.c:3280:1 in ucl.h
// ucl_array_find_index at ucl_util.c:3361:1 in ucl.h
// ucl_array_size at ucl_util.c:3345:1 in ucl.h
// ucl_object_tolstring at ucl_util.c:3588:1 in ucl.h
// ucl_array_head at ucl_util.c:3280:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_typed_new at ucl_util.c:2998:1 in ucl.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ucl.h>

static ucl_object_t* create_dummy_ucl_array(const uint8_t *Data, size_t Size) {
    ucl_object_t *array = ucl_object_typed_new(UCL_ARRAY);
    if (array == NULL) return NULL;

    for (size_t i = 0; i < Size; i++) {
        ucl_object_t *element = ucl_object_fromstring_common((const char *)&Data[i], 1, UCL_STRING_RAW);
        if (element == NULL) continue;

        ucl_array_append(array, element);
    }

    return array;
}

int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    ucl_object_t *ucl_array = create_dummy_ucl_array(Data, Size);
    if (ucl_array == NULL) return 0;

    unsigned int array_size = ucl_array_size(ucl_array);

    if (array_size > 0) {
        unsigned int index = Data[0] % array_size; // Simple index within range
        const ucl_object_t *obj_at_index = ucl_array_find_index(ucl_array, index);

        array_size = ucl_array_size(ucl_array);

        size_t str_len = 0;
        const char *string_rep = ucl_object_tolstring(obj_at_index, &str_len);

        const ucl_object_t *head = ucl_array_head(ucl_array);

        index = (index + 1) % array_size; // Change index to explore more states
        obj_at_index = ucl_array_find_index(ucl_array, index);

        array_size = ucl_array_size(ucl_array);

        string_rep = ucl_object_tolstring(obj_at_index, &str_len);

        head = ucl_array_head(ucl_array);
    }

    ucl_object_unref(ucl_array);

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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
