// This fuzz driver is generated for library hoextdown, aiming to fuzz the following functions:
// hoedown_stack_uninit at stack.c:24:1 in stack.h
// hoedown_hash_new at hash.c:131:1 in hash.h
// hoedown_hash_find at hash.c:206:1 in hash.h
// hoedown_hash_add at hash.c:179:1 in hash.h
// hoedown_malloc at buffer.c:9:1 in buffer.h
// hoedown_hash_free at hash.c:161:1 in hash.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"
#include "buffer.h"
#include "stack.h"

static void fuzz_hoedown_stack_uninit(hoedown_stack *st) {
    if (st) {
        hoedown_stack_uninit(st);
    }
}

static hoedown_hash* fuzz_hoedown_hash_new(size_t size) {
    return hoedown_hash_new(size);
}

static void* fuzz_hoedown_hash_find(hoedown_hash *hash, char *key, size_t key_len) {
    if (hash && key) {
        return hoedown_hash_find(hash, key, key_len);
    }
    return NULL;
}

static int fuzz_hoedown_hash_add(hoedown_hash *hash, const char *key, size_t key_len, void *value, hoedown_hash_value_destruct *destruct) {
    if (hash && key) {
        return hoedown_hash_add(hash, key, key_len, value, destruct);
    }
    return 1;
}

static void* fuzz_hoedown_malloc(size_t size) {
    return hoedown_malloc(size);
}

static void fuzz_hoedown_hash_free(hoedown_hash *hash) {
    if (hash) {
        hoedown_hash_free(hash);
    }
}

int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    size_t hash_size = Data[0];
    hoedown_hash *hash = fuzz_hoedown_hash_new(hash_size);

    if (hash) {
        if (Size > 1) {
            char *key = (char*)Data + 1;
            size_t key_len = Size - 1;

            void *value = fuzz_hoedown_malloc(10);
            if (value) {
                int add_result = fuzz_hoedown_hash_add(hash, key, key_len, value, NULL);
                void *found_value = fuzz_hoedown_hash_find(hash, key, key_len);

                if (add_result == 0 && found_value != NULL) {
                    // Successfully added and found the value
                }
                free(value); // Free the allocated memory
            }
        }
        fuzz_hoedown_hash_free(hash);
    }

    hoedown_stack stack;
    stack.item = (void **)fuzz_hoedown_malloc(sizeof(void *) * 10);
    stack.size = 0;
    stack.asize = 10;

    fuzz_hoedown_stack_uninit(&stack);

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
    