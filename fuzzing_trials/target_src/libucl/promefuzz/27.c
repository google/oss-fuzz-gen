// This fuzz driver is generated for library libucl, aiming to fuzz the following functions:
// ucl_object_new_full at ucl_util.c:3004:1 in ucl.h
// ucl_object_merge at ucl_util.c:2549:6 in ucl.h
// ucl_array_append at ucl_util.c:3153:6 in ucl.h
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
#include <stdbool.h>
#include "ucl.h"

static ucl_object_t* create_random_ucl_object(const uint8_t *Data, size_t Size, size_t *Offset) {
    if (*Offset >= Size) return NULL;
    
    ucl_type_t type = (ucl_type_t)(Data[*Offset] % (UCL_NULL + 1));
    (*Offset)++;
    
    unsigned priority = 0;
    if (*Offset < Size) {
        priority = Data[*Offset];
        (*Offset)++;
    }

    return ucl_object_new_full(type, priority);
}

int LLVMFuzzerTestOneInput_27(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;

    size_t offset = 0;

    // Create UCL objects
    ucl_object_t *obj1 = create_random_ucl_object(Data, Size, &offset);
    ucl_object_t *obj2 = create_random_ucl_object(Data, Size, &offset);

    if (obj1 && obj2) {
        // Merge objects
        bool copy = Data[offset % Size] % 2 == 0;
        ucl_object_merge(obj1, obj2, copy);

        // Append obj2 to obj1 if obj1 is an array
        if (obj1->type == UCL_ARRAY) {
            ucl_array_append(obj1, obj2);
        } else {
            // Unreference obj2 if not appended to avoid double free
            ucl_object_unref(obj2);
        }
    } else {
        // Unreference obj2 if it was created but obj1 was not
        if (obj2) ucl_object_unref(obj2);
    }

    // Unreference obj1
    if (obj1) ucl_object_unref(obj1);

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

    LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
