#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include "janet.h"

static JanetAbstractType dummy_abstract_type = {
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

int LLVMFuzzerTestOneInput_912(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return 0;

    size_t allocation_size = *((size_t *)Data);

    // Ensure allocation size is within a reasonable range
    if (allocation_size > 1024 * 1024) return 0;

    // Initialize Janet VM
    janet_init();

    void *ptr = janet_smalloc(allocation_size);
    if (ptr) {
        janet_gcpressure(allocation_size);
        ptr = janet_srealloc(ptr, allocation_size / 2);
        // Proper cleanup with Janet's memory management
        janet_srealloc(ptr, 0);
    }

    void *abstract_ptr = janet_abstract_begin(&dummy_abstract_type, allocation_size);
    if (abstract_ptr) {
        janet_gcpressure(allocation_size);
        // No explicit deallocation needed for abstract types, handled by Janet's GC
    }

    void *malloc_ptr = janet_malloc(allocation_size);
    if (malloc_ptr) {
        janet_gcpressure(allocation_size);
        free(malloc_ptr); // Assuming janet_malloc uses standard free for cleanup
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

    LLVMFuzzerTestOneInput_912(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
