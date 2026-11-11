// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_dictionary_view at janet.c:34506:5 in janet.h
// janet_sorted_keys at janet.c:34589:9 in janet.h
// janet_dictionary_next at janet.c:34030:16 in janet.h
// janet_dictionary_next at janet.c:34030:16 in janet.h
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

static Janet generate_random_janet(const uint8_t *Data, size_t Size) {
    Janet janet;
    if (Size < sizeof(Janet)) {
        janet.u64 = 0;
    } else {
        janet.u64 = *((uint64_t *)Data);
    }
    return janet;
}

static JanetKV *generate_random_janetkv(const uint8_t *Data, size_t Size) {
    JanetKV *kv = (JanetKV *)malloc(sizeof(JanetKV));
    if (kv && Size >= sizeof(JanetKV)) {
        kv->key = generate_random_janet(Data, Size);
        kv->value = generate_random_janet(Data + sizeof(Janet), Size - sizeof(Janet));
    }
    return kv;
}

int LLVMFuzzerTestOneInput_534(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetKV)) {
        return 0;
    }

    // Prepare dummy file
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return 0;
    fwrite(Data, 1, Size, file);
    fclose(file);

    // Prepare environment for janet_dictionary_view
    const JanetKV *data = NULL;
    int32_t len = 0, cap = 0;
    Janet tab = generate_random_janet(Data, Size);
    janet_dictionary_view(tab, &data, &len, &cap);

    // Prepare environment for janet_sorted_keys
    int32_t *index_buffer = (int32_t *)malloc(len * sizeof(int32_t));
    if (index_buffer) {
        janet_sorted_keys(data, len, index_buffer);
        free(index_buffer);
    }

    // Prepare environment for janet_dictionary_next
    const JanetKV *next_kv = janet_dictionary_next(data, cap, NULL);
    while (next_kv) {
        next_kv = janet_dictionary_next(data, cap, next_kv);
    }

    // Cleanup
    free((void *)data);
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

        LLVMFuzzerTestOneInput_534(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    