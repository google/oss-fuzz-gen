// This fuzz driver is generated for library libucl, aiming to fuzz the following functions:
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_typed_new at ucl_util.c:2998:1 in ucl.h
// ucl_object_ref at ucl_util.c:3613:1 in ucl.h
// ucl_object_fromstring_common at ucl_util.c:2225:1 in ucl.h
// ucl_object_insert_key at ucl_util.c:2531:6 in ucl.h
// ucl_object_frombool at ucl_util.c:3140:1 in ucl.h
// ucl_object_insert_key at ucl_util.c:2531:6 in ucl.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ucl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

static void perform_cleanup(ucl_object_t *obj) {
    if (obj != NULL) {
        ucl_object_unref(obj);
    }
}

int LLVMFuzzerTestOneInput_18(const uint8_t *Data, size_t Size) {
    if (Size == 0) {
        return 0;
    }

    // Initialize UCL object
    ucl_object_t *top = ucl_object_typed_new(UCL_OBJECT);
    if (top == NULL) {
        return 0;
    }

    // Create initial reference
    ucl_object_t *ref = ucl_object_ref(top);
    if (ref == NULL) {
        perform_cleanup(top);
        return 0;
    }

    // Use a portion of the data as a string
    const char *str = (const char *)Data;
    size_t str_len = Size;
    enum ucl_string_flags flags = UCL_STRING_RAW;

    // Insert multiple keys with string values
    for (int i = 0; i < 5; ++i) {
        char key[16];
        snprintf(key, sizeof(key), "key%d", i);

        ucl_object_t *str_obj = ucl_object_fromstring_common(str, str_len, flags);
        if (str_obj == NULL) {
            perform_cleanup(ref);
            return 0;
        }

        if (!ucl_object_insert_key(top, str_obj, key, 0, true)) {
            perform_cleanup(str_obj);
            perform_cleanup(ref);
            return 0;
        }
    }

    // Insert a boolean value
    ucl_object_t *bool_obj = ucl_object_frombool(true);
    if (bool_obj == NULL) {
        perform_cleanup(ref);
        return 0;
    }

    if (!ucl_object_insert_key(top, bool_obj, "bool_key", 0, true)) {
        perform_cleanup(bool_obj);
        perform_cleanup(ref);
        return 0;
    }

    // Cleanup
    perform_cleanup(ref);
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
