#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_990(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(Janet) * 3 + sizeof(const char *)) return 0;

    // Initialize Janet VM
    janet_init();

    // Prepare JanetFiber
    JanetFiber fiber;
    memset(&fiber, 0, sizeof(JanetFiber));

    // Prepare JanetTryState
    JanetTryState tryState;
    janet_try_init(&tryState);

    // Prepare Janet inputs
    Janet in = *(Janet *)(Data);
    Janet out;

    // Fuzz janet_step
    if (fiber.data) {
        janet_step(&fiber, in, &out);
    }

    // Fuzz janet_restore
    janet_restore(&tryState);

    // Fuzz janet_cancel
    if (fiber.data) {
        janet_cancel(&fiber, in);
    }

    // Fuzz janet_stacktrace
    if (fiber.data) {
        janet_stacktrace(&fiber, in);
    }

    // Ensure prefix is null-terminated
    size_t prefix_length = Size - sizeof(Janet) * 3;
    char *prefix = (char *)malloc(prefix_length + 1);
    if (prefix) {
        memcpy(prefix, Data + sizeof(Janet) * 2, prefix_length);
        prefix[prefix_length] = '\0';

        // Fuzz janet_stacktrace_ext
        if (fiber.data) {
            janet_stacktrace_ext(&fiber, in, prefix);
        }

        free(prefix);
    }

    // Write to dummy file for functions requiring file operations
    write_dummy_file(Data, Size);

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

    LLVMFuzzerTestOneInput_990(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
