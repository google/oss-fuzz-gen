// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_init at vm.c:1652:5 in janet.h
// janet_vm_alloc at janet.c:31204:10 in janet.h
// janet_symbol at janet.c:32957:16 in janet.h
// janet_clear_memory at gc.c:668:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include "janet.h"

static void fuzz_janet_init(void) {
    janet_init();
}

static void fuzz_janet_vm_alloc(void) {
    JanetVM *vm = janet_vm_alloc();
    if (vm != NULL) {
        // Optionally perform operations on the VM
    }
}

static void fuzz_janet_realloc(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return;

    size_t new_size = *((size_t *)Data);
    void *ptr = janet_realloc(NULL, new_size);
    if (ptr != NULL) {
        janet_realloc(ptr, 0); // Free the memory
    }
}

static void fuzz_janet_symbol(const uint8_t *Data, size_t Size) {
    janet_symbol(Data, (int32_t)Size);
}

static void fuzz_janet_clear_memory(void) {
    janet_clear_memory();
}

int LLVMFuzzerTestOneInput_218(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    // Initialize the Janet VM
    fuzz_janet_init();

    // Fuzz various Janet functions
    fuzz_janet_vm_alloc();
    fuzz_janet_realloc(Data, Size);
    fuzz_janet_symbol(Data, Size);
    fuzz_janet_clear_memory();

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

        LLVMFuzzerTestOneInput_218(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    