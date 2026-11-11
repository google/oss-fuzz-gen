// This fuzz driver is generated for library libucl, aiming to fuzz the following functions:
// ucl_object_new_full at ucl_util.c:3004:1 in ucl.h
// ucl_object_new_full at ucl_util.c:3004:1 in ucl.h
// ucl_object_insert_key at ucl_util.c:2531:6 in ucl.h
// ucl_object_lookup_len at ucl_util.c:2654:1 in ucl.h
// ucl_object_pop_key at ucl_util.c:2526:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_pop_key at ucl_util.c:2526:1 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
// ucl_object_lookup_len at ucl_util.c:2654:1 in ucl.h
// ucl_object_new_full at ucl_util.c:3004:1 in ucl.h
// ucl_object_insert_key at ucl_util.c:2531:6 in ucl.h
// ucl_object_unref at ucl_util.c:3719:6 in ucl.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ucl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

static void fuzz_ucl_object_functions(const uint8_t *Data, size_t Size) {
    // Create a new UCL object
    ucl_object_t *top = ucl_object_new_full(UCL_OBJECT, 0);
    if (top == NULL) return;

    // Define a key for operations
    const char *key = "test_key";
    size_t key_len = strlen(key);

    // Insert a new object with the key
    ucl_object_t *new_obj = ucl_object_new_full(UCL_STRING, 0);
    if (new_obj != NULL) {
        new_obj->value.sv = "test_value";
        ucl_object_insert_key(top, new_obj, key, key_len, true);
    }

    // Lookup the object by key
    const ucl_object_t *found_obj = ucl_object_lookup_len(top, key, key_len);

    // Pop the key
    ucl_object_t *popped_obj1 = ucl_object_pop_key(top, key);
    if (popped_obj1 != NULL) {
        ucl_object_unref(popped_obj1);
    }

    // Pop the key again
    ucl_object_t *popped_obj2 = ucl_object_pop_key(top, key);
    if (popped_obj2 != NULL) {
        ucl_object_unref(popped_obj2);
    }

    // Lookup the object by key again
    found_obj = ucl_object_lookup_len(top, key, key_len);

    // Create another new UCL object
    ucl_object_t *another_obj = ucl_object_new_full(UCL_INT, 0);
    if (another_obj != NULL) {
        another_obj->value.iv = 12345;
        ucl_object_insert_key(top, another_obj, key, 0, true);
    }

    // Cleanup
    ucl_object_unref(top);
}

int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    fuzz_ucl_object_functions(Data, Size);

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

    LLVMFuzzerTestOneInput_11(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
