// This fuzz driver is generated for library libucl, aiming to fuzz the following functions:
// ucl_object_typed_new at ucl_util.c:2998:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_fromstring_common at ucl_util.c:2225:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_replace_key at ucl_util.c:2543:6 in ucl.h
// ucl_object_fromstring_common at ucl_util.c:2225:1 in ucl.h
// ucl_object_insert_key at ucl_util.c:2531:6 in ucl.h
// ucl_object_typed_new at ucl_util.c:2998:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "ucl.h"

static bool write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) {
        return false;
    }
    fwrite(Data, 1, Size, file);
    fclose(file);
    return true;
}

int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare environment
    ucl_object_t *obj = ucl_object_typed_new(UCL_OBJECT);
    if (!obj) return 0;

    // Write to dummy file
    if (!write_dummy_file(Data, Size)) {
        ucl_object_unref(obj);
        return 0;
    }

    // Use part of Data as key
    size_t keylen = Size > 1 ? Size - 1 : 0;
    char *key = (char *)malloc(keylen + 1);
    if (!key) {
        ucl_object_unref(obj);
        return 0;
    }
    memcpy(key, Data, keylen);
    key[keylen] = '\0'; // Ensure null termination
    bool copy_key = true;

    // Create a string object
    ucl_object_t *str_obj = ucl_object_fromstring_common(key, keylen, UCL_STRING_RAW);
    if (!str_obj) {
        free(key);
        ucl_object_unref(obj);
        return 0;
    }

    // Replace key
    ucl_object_replace_key(obj, str_obj, key, keylen, copy_key);

    // Insert key-value pairs using ucl_object_insert_key
    for (int i = 0; i < 3; i++) {
        ucl_object_t *new_obj = ucl_object_fromstring_common(key, keylen, UCL_STRING_RAW);
        if (new_obj) {
            ucl_object_insert_key(obj, new_obj, key, keylen, copy_key);
        }
    }

    // Create a new typed object
    ucl_object_t *typed_obj = ucl_object_typed_new(UCL_INT);
    if (typed_obj) {
        ucl_object_unref(typed_obj);
    }

    // Cleanup
    free(key);
    ucl_object_unref(obj);

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

    LLVMFuzzerTestOneInput_23(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
