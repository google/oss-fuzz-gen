#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static Janet create_dummy_data_structure() {
    JanetArray *array = janet_array(10);
    for (int i = 0; i < 10; i++) {
        array->data[i] = janet_wrap_integer(i);
    }
    array->count = 10;
    return janet_wrap_array(array);
}

static Janet create_dummy_key(int index) {
    return janet_wrap_integer(index);
}

static void fuzz_janet_in(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;
    Janet ds = create_dummy_data_structure();
    int index = *((int *)Data) % 10;
    if (index < 0) index = -index; // Ensure index is non-negative
    Janet key = create_dummy_key(index);
    janet_in(ds, key);
}

static void fuzz_janet_unwrap_tuple(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;
    Janet x = *((Janet *)Data);
    if (janet_checktype(x, JANET_TUPLE)) {
        janet_unwrap_tuple(x);
    }
}

static void fuzz_janet_checktype(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) + sizeof(JanetType)) return;
    Janet x = *((Janet *)Data);
    JanetType type = *((JanetType *)(Data + sizeof(Janet)));
    if (type >= JANET_NUMBER && type <= JANET_POINTER) {
        janet_checktype(x, type);
    }
}

static void fuzz_janet_get(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return;
    Janet ds = create_dummy_data_structure();
    int index = *((int *)Data) % 10;
    if (index < 0) index = -index; // Ensure index is non-negative
    Janet key = create_dummy_key(index);
    janet_get(ds, key);
}

static void fuzz_janet_unwrap_abstract(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet)) return;
    Janet x = *((Janet *)Data);
    if (janet_checktype(x, JANET_ABSTRACT)) {
        janet_unwrap_abstract(x);
    }
}

int LLVMFuzzerTestOneInput_632(const uint8_t *Data, size_t Size) {
    static int janet_initialized = 0;
    if (!janet_initialized) {
        janet_init();
        janet_initialized = 1;
    }
    fuzz_janet_in(Data, Size);
    fuzz_janet_unwrap_tuple(Data, Size);
    fuzz_janet_checktype(Data, Size);
    fuzz_janet_get(Data, Size);
    fuzz_janet_unwrap_abstract(Data, Size);
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

    LLVMFuzzerTestOneInput_632(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
