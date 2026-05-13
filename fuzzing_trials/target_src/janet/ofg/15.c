#include <stdint.h>
#include <stddef.h>
#include <janet.h>

extern int janet_dictionary_view(Janet, const JanetKV **, int32_t *, int32_t *);

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet)) {
        return 0;
    }

    Janet janet_value;
    const JanetKV *kvs = NULL;
    int32_t count = 0;
    int32_t capacity = 0;

    // Copy data into a Janet value
    memcpy(&janet_value, data, sizeof(Janet));

    // Call the function-under-test
    janet_dictionary_view(janet_value, &kvs, &count, &capacity);

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

    LLVMFuzzerTestOneInput_15(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
