#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ucl.h"
#include <stdbool.h>

static ucl_object_t* create_dummy_ucl_object() {
    ucl_object_t *obj = (ucl_object_t *)malloc(sizeof(ucl_object_t));
    if (obj) {
        obj->type = UCL_OBJECT;
        obj->value.ov = NULL;
        obj->key = NULL;
        obj->next = NULL;
        obj->prev = NULL;
        obj->keylen = 0;
        obj->len = 0;
        obj->ref = 1;
        obj->flags = 0;
    }
    return obj;
}

static ucl_object_iter_t create_dummy_iterator(ucl_object_t *obj) {
    // Use the library's function to create a valid iterator for the object
    return ucl_object_iterate_new(obj);
}

int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there is at least some data

    // Create a dummy UCL object
    ucl_object_t *ucl_obj = create_dummy_ucl_object();
    if (!ucl_obj) return 0;

    // Create a valid iterator using the UCL object
    ucl_object_iter_t iter = create_dummy_iterator(ucl_obj);
    if (!iter) {
        free(ucl_obj);
        return 0;
    }

    // Iterate and check exceptions
    for (int i = 0; i < 4; i++) {
        const ucl_object_t *next_obj = ucl_object_iterate_safe(iter, Data[0] % 2);
        if (ucl_object_iter_chk_excpn(iter)) {
            break; // Exit if an exception occurred
        }
        ucl_type_t obj_type = ucl_object_type(next_obj);
        (void)obj_type; // Use obj_type to avoid unused variable warning
    }

    // Free the iterator
    ucl_object_iterate_free(iter);
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

    LLVMFuzzerTestOneInput_18(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
