#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <janet.h>

extern const JanetKV *janet_dictionary_next(const JanetKV *, int32_t, const JanetKV *);

int LLVMFuzzerTestOneInput_375(const uint8_t *data, size_t size) {
    if (size < sizeof(JanetKV) * 2 + sizeof(int32_t)) {
        return 0;
    }

    // Initialize Janet library
    janet_init();

    // Allocate memory for JanetKV structures
    JanetKV *dict = (JanetKV *)malloc(sizeof(JanetKV) * 2);
    if (!dict) {
        return 0;
    }

    // Initialize JanetKV entries with non-NULL values
    for (int i = 0; i < 2; i++) {
        dict[i].key = janet_wrap_nil();
        dict[i].value = janet_wrap_nil();
    }

    // Extract an integer from the data for the index
    int32_t index = *((int32_t *)data);
    data += sizeof(int32_t);

    // Create a pointer to a JanetKV entry for the third parameter
    const JanetKV *current = (const JanetKV *)(data);

    // Call the function-under-test
    const JanetKV *result = janet_dictionary_next(dict, index, current);

    // Clean up
    free(dict);
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

    LLVMFuzzerTestOneInput_375(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
