#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "ucl.h"

static ucl_object_t *create_dummy_ucl_object() {
    ucl_object_t *obj = (ucl_object_t *)malloc(sizeof(ucl_object_t));
    if (obj) {
        obj->value.iv = 123; // Example integer value
        obj->key = "dummy";
        obj->keylen = strlen(obj->key);
        obj->len = 1;
        obj->ref = 1;
        obj->flags = 0;
        obj->type = UCL_INT;
        obj->next = NULL;
        obj->prev = NULL;
    }
    return obj;
}

int LLVMFuzzerTestOneInput_8(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there is at least some data

    // Create a dummy UCL object for testing
    ucl_object_t *obj = create_dummy_ucl_object();
    if (!obj) return 0;

    // Convert the first byte to a path string
    char path[2] = { (char)Data[0], '\0' };

    // Invoke ucl_object_toint
    int64_t int_value = ucl_object_toint(obj);

    // Invoke ucl_object_lookup_path
    const ucl_object_t *found_obj = ucl_object_lookup_path(obj, path);

    // Invoke ucl_object_toint again if a valid object is found
    if (found_obj) {
        int_value = ucl_object_toint(found_obj);
    }

    // Repeat invoking the functions as per the sequence
    found_obj = ucl_object_lookup_path(obj, path);
    if (found_obj) {
        int_value = ucl_object_toint(found_obj);
    }

    found_obj = ucl_object_lookup_path(obj, path);
    found_obj = ucl_object_lookup_path(obj, path);

    // Create an iterator
    ucl_object_iter_t iter = ucl_object_iterate_new(obj);
    if (iter) {
        // Safely iterate over the object
        const ucl_object_t *iter_obj = ucl_object_iterate_safe(iter, true);
        
        // Free the iterator to prevent memory leak
        free(iter);
    }

    // Clean up
    free(obj);
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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
