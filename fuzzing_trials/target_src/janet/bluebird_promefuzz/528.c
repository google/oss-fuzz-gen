#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "janet.h"

static int initialized = 0;

static void initialize_janet() {
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

static void fuzz_janet_in(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    initialize_janet();

    // Create a dummy Janet array for testing
    JanetArray *array = janet_array(10);
    for (int i = 0; i < 10; i++) {
        array->data[i] = janet_wrap_integer(i);
    }
    array->count = 10;

    // Use the first byte as an index
    int32_t index = Data[0] % 10;
    Janet key = janet_wrap_integer(index);

    // Attempt to retrieve a value
    Janet value = janet_in(janet_wrap_array(array), key);
    janet_truthy(value);

    // No longer call janet_collect() here to avoid GC issues
}

static void fuzz_janet_hash(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    initialize_janet();

    // Wrap data in a Janet string
    Janet str = janet_wrap_string(janet_string(Data, Size));

    // Compute hash
    int32_t hash = janet_hash(str);

    // Use the hash somehow
    (void)hash;
}

static void fuzz_janet_checktype(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    initialize_janet();

    // Create a Janet value
    Janet value = janet_wrap_integer((int32_t)Data[0]);

    // Check if it is of type JANET_NUMBER
    int is_number = janet_checktype(value, JANET_NUMBER);

    // Use the result somehow
    (void)is_number;
}

static void fuzz_janet_get(const uint8_t *Data, size_t Size) {
    if (Size < 2) return;

    initialize_janet();

    // Create a dummy Janet array
    JanetArray *array = janet_array(10);
    for (int i = 0; i < 10; i++) {
        array->data[i] = janet_wrap_integer(i);
    }
    array->count = 10;

    // Use the first byte as an index
    int32_t index = Data[0] % 10;
    Janet key = janet_wrap_integer(index);

    // Attempt to retrieve a value
    Janet value = janet_get(janet_wrap_array(array), key);
    janet_truthy(value);

    // No longer call janet_collect() here to avoid GC issues
}

static void fuzz_janet_truthy(const uint8_t *Data, size_t Size) {
    if (Size < 1) return;

    initialize_janet();

    // Wrap data in a Janet string
    Janet str = janet_wrap_string(janet_string(Data, Size));

    // Check truthiness
    int truthy = janet_truthy(str);

    // Use the result somehow
    (void)truthy;
}

static void fuzz_janet_wrap_integer(const uint8_t *Data, size_t Size) {
    if (Size < 4) return;

    initialize_janet();

    // Convert bytes to int32_t
    int32_t num = (int32_t)(Data[0] | (Data[1] << 8) | (Data[2] << 16) | (Data[3] << 24));

    // Wrap integer in a Janet value
    Janet wrapped = janet_wrap_integer(num);

    // Use the wrapped value somehow
    (void)wrapped;
}

int LLVMFuzzerTestOneInput_528(const uint8_t *Data, size_t Size) {
    fuzz_janet_in(Data, Size);
    fuzz_janet_hash(Data, Size);
    fuzz_janet_checktype(Data, Size);
    fuzz_janet_get(Data, Size);
    fuzz_janet_truthy(Data, Size);
    fuzz_janet_wrap_integer(Data, Size);
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

    LLVMFuzzerTestOneInput_528(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
