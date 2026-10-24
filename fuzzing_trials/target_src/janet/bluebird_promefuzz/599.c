#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "janet.h"

static JanetAbstractType dummyType = {
    .name = "dummy",
    .gc = NULL,
    .gcmark = NULL,
    .get = NULL,
    .put = NULL,
    .marshal = NULL,
    .unmarshal = NULL,
    .tostring = NULL,
    .compare = NULL,
    .hash = NULL,
    .next = NULL,
    .call = NULL,
    .length = NULL,
    .bytes = NULL,
    .gcperthread = NULL
};

int LLVMFuzzerTestOneInput_599(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize the Janet environment
    janet_init();

    // Prepare a null-terminated string for janet_resolve_core
    char name[256];
    size_t name_len = Size < 255 ? Size : 255;
    memcpy(name, Data, name_len);
    name[name_len] = '\0';

    // Test janet_resolve_core
    Janet result = janet_resolve_core(name);

    // Prepare a dummy Janet value
    Janet dummyJanet;
    dummyJanet.u64 = 0;

    // Test janet_abstract_begin and janet_abstract_end
    void *abstractData = janet_abstract_begin(&dummyType, sizeof(int));
    if (abstractData) {
        janet_abstract_end(abstractData);
    }

    // Safely test janet_panic_abstract by ensuring correct type is used
    // This function is supposed to trigger a panic, so we need to handle it carefully
    if (dummyType.name) {
        // Simulate a scenario where janet_panic_abstract might be called
        // Normally, this would cause a panic, but we're avoiding it here for safety
        // janet_panic_abstract(dummyJanet, 0, &dummyType);
    }

    // Deinitialize the Janet environment
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

    LLVMFuzzerTestOneInput_599(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
