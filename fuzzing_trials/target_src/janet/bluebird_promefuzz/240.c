#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

static Janet create_janet_string(const uint8_t *data, size_t size) {
    return janet_wrap_string(janet_string(data, size));
}

static JanetTable *create_janet_table() {
    JanetTable *table = janet_table(0);
    return table;
}

int LLVMFuzzerTestOneInput_240(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Initialize Janet VM
    janet_init();

    // Fuzz janet_unwrap_string
    Janet janetString = create_janet_string(Data, Size);
    JanetString unwrappedString = janet_unwrap_string(janetString);

    // Fuzz janet_compile
    JanetTable *env = create_janet_table();
    JanetCompileResult compileResult = janet_compile(janetString, env, unwrappedString);

    // Fuzz janet_getstring
    Janet argv[1] = {janetString};
    JanetString getStringResult = janet_getstring(argv, 0);

    // Fuzz janet_to_string
    JanetString toStringResult = janet_to_string(janetString);

    // Fuzz janet_string_equal
    int stringEqualResult = janet_string_equal(unwrappedString, getStringResult);

    // Fuzz janet_description
    JanetString descriptionResult = janet_description(janetString);

    // Cleanup
    // No need to manually free env->data as it is managed by the Janet GC

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

    LLVMFuzzerTestOneInput_240(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
