// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_optstruct at janet.c:4528:1 in janet.h
// janet_getstruct at janet.c:4515:1 in janet.h
// janet_struct_put at janet.c:32598:6 in janet.h
// janet_struct_get_ex at janet.c:32643:7 in janet.h
// janet_struct_find at janet.c:32513:16 in janet.h
// janet_struct_get at janet.c:32632:7 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "janet.h"

static Janet random_janet() {
    Janet j;
    switch (rand() % 4) {
        case 0:
            j.u64 = (uint64_t)rand();
            break;
        case 1:
            j.i64 = (int64_t)rand();
            break;
        case 2:
            j.number = (double)rand() / RAND_MAX;
            break;
        case 3:
            j.pointer = NULL;
            break;
    }
    return j;
}

static JanetKV *create_janet_kv_array(int size) {
    JanetKV *array = malloc(size * sizeof(JanetKV));
    for (int i = 0; i < size; i++) {
        array[i].key = random_janet();
        array[i].value = random_janet();
    }
    return array;
}

int LLVMFuzzerTestOneInput_584(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t) * 2) return 0;

    int32_t n = *((int32_t *)Data);
    int32_t argc = *((int32_t *)(Data + sizeof(int32_t)));
    Data += sizeof(int32_t) * 2;
    Size -= sizeof(int32_t) * 2;

    Janet *argv = malloc(argc * sizeof(Janet));
    for (int i = 0; i < argc; i++) {
        argv[i] = random_janet();
    }

    JanetStruct default_struct = create_janet_kv_array(4);
    JanetStruct js = janet_optstruct(argv, argc, n, default_struct);

    if (argc > 0 && n >= 0 && n < argc) {
        JanetStruct js_get = janet_getstruct(argv, n);
    }

    JanetKV *kv_array = create_janet_kv_array(4);
    Janet key = random_janet();
    Janet value = random_janet();
    janet_struct_put(kv_array, key, value);

    JanetStruct which;
    Janet result = janet_struct_get_ex(js, key, &which);

    const JanetKV *found = janet_struct_find(js, key);

    Janet value_get = janet_struct_get(js, key);

    free((void *)default_struct);
    free(argv);
    free(kv_array);

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

        LLVMFuzzerTestOneInput_584(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    