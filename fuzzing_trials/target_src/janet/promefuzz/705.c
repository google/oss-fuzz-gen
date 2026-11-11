// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_getarray at janet.c:4512:1 in janet.h
// janet_array_ensure at janet.c:1589:6 in janet.h
// janet_array_weak at janet.c:1569:13 in janet.h
// janet_optarray at janet.c:4540:1 in janet.h
// janet_array_setcount at janet.c:1606:6 in janet.h
// janet_array_setcount at janet.c:1606:6 in janet.h
// janet_array at janet.c:1562:13 in janet.h
// janet_deinit at vm.c:1732:6 in janet.h
// janet_array at janet.c:1562:13 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "janet.h"

static JanetArray *create_dummy_janet_array(int32_t capacity) {
    JanetArray *array = janet_array(capacity);
    if (array) {
        for (int32_t i = 0; i < capacity; i++) {
            array->data[i].u64 = (uint64_t)i;
        }
        array->count = capacity;
    }
    return array;
}

int LLVMFuzzerTestOneInput_705(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t) * 5) {
        return 0;
    }

    janet_init();

    int32_t idx1 = ((int32_t *)Data)[0];
    int32_t idx2 = ((int32_t *)Data)[1];
    int32_t capacity1 = ((int32_t *)Data)[2];
    int32_t capacity2 = ((int32_t *)Data)[3];
    int32_t dflt_len = ((int32_t *)Data)[4];
    
    JanetArray *array1 = create_dummy_janet_array(capacity1);
    JanetArray *array2 = create_dummy_janet_array(capacity2);

    if (array1 && array1->count > 0) {
        janet_getarray(array1->data, idx1 % array1->count);
    }

    janet_array_ensure(array2, capacity1, capacity2);

    JanetArray *weakArray = janet_array_weak(capacity1);

    JanetArray *optArray = janet_optarray(array1->data, array1->count, idx2, dflt_len);

    if (weakArray) {
        janet_array_setcount(weakArray, capacity2);
    }

    if (array1) {
        janet_array_setcount(array1, capacity2);
    }

    janet_array(capacity1);

    free(array1);
    free(array2);
    free(weakArray);

    janet_deinit();

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

        LLVMFuzzerTestOneInput_705(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    