// This fuzz driver is generated for library libucl, aiming to fuzz the following functions:
// ucl_object_new at ucl_util.c:2992:1 in ucl.h
// ucl_object_new at ucl_util.c:2992:1 in ucl.h
// ucl_object_new at ucl_util.c:2992:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_insert_key at ucl_util.c:2531:6 in ucl.h
// ucl_object_insert_key at ucl_util.c:2531:6 in ucl.h
// ucl_object_new_userdata at ucl_util.c:3067:1 in ucl.h
// ucl_object_insert_key at ucl_util.c:2531:6 in ucl.h
// ucl_object_fromlstring at ucl_util.c:3106:1 in ucl.h
// ucl_object_insert_key at ucl_util.c:2531:6 in ucl.h
// ucl_object_new at ucl_util.c:2992:1 in ucl.h
// ucl_object_insert_key at ucl_util.c:2531:6 in ucl.h
// ucl_object_lookup_any at ucl_util.c:2681:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ucl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

static void dummy_dtor(void *ud) {
    // Dummy destructor function
}

static const char *dummy_emitter(void *ud) {
    // Dummy emitter function
    return NULL;
}

int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    ucl_object_t *top = ucl_object_new();
    ucl_object_t *elt1 = ucl_object_new();
    ucl_object_t *elt2 = ucl_object_new();

    if (!top || !elt1 || !elt2) {
        ucl_object_unref(top);
        ucl_object_unref(elt1);
        ucl_object_unref(elt2);
        return 0;
    }

    const char *key1 = "key1";
    const char *key2 = "key2";
    const char *key3 = "key3";
    const char *key4 = "key4";
    const char *key5 = "key5";

    ucl_object_insert_key(top, elt1, key1, 0, true);
    ucl_object_insert_key(top, elt2, key2, 0, true);

    ucl_object_t *userdata_obj = ucl_object_new_userdata(dummy_dtor, dummy_emitter, (void *)Data);
    if (userdata_obj) {
        ucl_object_insert_key(top, userdata_obj, key3, 0, true);
    }

    ucl_object_t *str_obj = ucl_object_fromlstring((const char *)Data, Size);
    if (str_obj) {
        ucl_object_insert_key(top, str_obj, key4, 0, true);
    }

    ucl_object_t *elt5 = ucl_object_new();
    if (elt5) {
        ucl_object_insert_key(top, elt5, key5, 0, true);
    }

    const ucl_object_t *result = ucl_object_lookup_any(top, key1, key2, key3, key4, key5, NULL);

    // Unref only the top object, as it will unref all inserted elements
    ucl_object_unref(top);

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

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
