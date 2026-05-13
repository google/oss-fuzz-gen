#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "janet.h"

static Janet generate_random_janet(const uint8_t **Data, size_t *Size) {
    Janet result;
    if (*Size < 1) return janet_wrap_nil();
    
    uint8_t type = (*Data)[0] % 4;
    *Data += 1;
    *Size -= 1;

    switch (type) {
        case 0: // wrap a number
            if (*Size < sizeof(double)) return janet_wrap_nil();
            double num;
            memcpy(&num, *Data, sizeof(double));
            *Data += sizeof(double);
            *Size -= sizeof(double);
            return janet_wrap_number(num);
        case 1: // wrap an integer
            if (*Size < sizeof(int64_t)) return janet_wrap_nil();
            int64_t i64;
            memcpy(&i64, *Data, sizeof(int64_t));
            *Data += sizeof(int64_t);
            *Size -= sizeof(int64_t);
            return janet_wrap_integer(i64);
        case 2: // wrap a u64
            if (*Size < sizeof(uint64_t)) return janet_wrap_nil();
            uint64_t u64;
            memcpy(&u64, *Data, sizeof(uint64_t));
            *Data += sizeof(uint64_t);
            *Size -= sizeof(uint64_t);
            return janet_wrap_integer((int64_t)u64); // Use integer to avoid janet_abstract
        default: // wrap a pointer
            if (*Size < sizeof(void *)) return janet_wrap_nil();
            void *ptr;
            memcpy(&ptr, *Data, sizeof(void *));
            *Data += sizeof(void *);
            *Size -= sizeof(void *);
            return janet_wrap_pointer(ptr);
    }
}

int LLVMFuzzerTestOneInput_998(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t) + 1) return 0;

    // Initialize Janet VM
    janet_init();

    // Prepare a dummy Janet array
    Janet argv[10];
    for (int i = 0; i < 10; i++) {
        argv[i] = generate_random_janet(&Data, &Size);
    }

    // Ensure we have enough data left for the index
    if (Size < sizeof(int32_t)) {
        janet_deinit();
        return 0;
    }

    // Use the first byte as the index
    int32_t n;
    memcpy(&n, Data, sizeof(int32_t));
    n = n % 10; // Ensure within bounds
    Data += sizeof(int32_t);
    Size -= sizeof(int32_t);

    // Test janet_getstruct
    JanetStruct js = NULL;
    if (n >= 0 && n < 10 && janet_checktype(argv[n], JANET_STRUCT)) {
        js = janet_unwrap_struct(argv[n]);
    }

    if (js != NULL) {
        // Test janet_wrap_struct
        Janet wrapped = janet_wrap_struct(js);

        // Test janet_struct_rawget
        Janet key = generate_random_janet(&Data, &Size);
        Janet value = janet_struct_rawget(js, key);

        // Test janet_struct_find
        const JanetKV *found = janet_struct_find(js, key);

        // Test janet_struct_get
        Janet value2 = janet_struct_get(js, key);

        // Test janet_unwrap_struct
        JanetStruct unwrapped = janet_unwrap_struct(wrapped);
    }

    // Deinitialize Janet VM
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_998(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
