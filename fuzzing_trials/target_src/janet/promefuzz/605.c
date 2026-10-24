// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_vm_alloc at janet.c:31204:10 in janet.h
// janet_vm_alloc at janet.c:31204:10 in janet.h
// janet_local_vm at janet.c:31200:10 in janet.h
// janet_vm_free at janet.c:31212:6 in janet.h
// janet_vm_free at janet.c:31212:6 in janet.h
// janet_vm_load at janet.c:31220:6 in janet.h
// janet_interpreter_interrupt at janet.c:31227:6 in janet.h
// janet_interpreter_interrupt at janet.c:31227:6 in janet.h
// janet_vm_save at janet.c:31216:6 in janet.h
// janet_vm_free at janet.c:31212:6 in janet.h
// janet_vm_free at janet.c:31212:6 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_605(const uint8_t *Data, size_t Size) {
    // Prepare environment
    JanetVM *vm1 = janet_vm_alloc();
    JanetVM *vm2 = janet_vm_alloc();
    if (!vm1 || !vm2) {
        // Handle memory allocation failure
        return 0;
    }

    // Test janet_local_vm
    JanetVM *local_vm = janet_local_vm();
    if (!local_vm) {
        // Handle unexpected null return
        janet_vm_free(vm1);
        janet_vm_free(vm2);
        return 0;
    }

    // Test janet_vm_load
    janet_vm_load(vm1);

    // Test janet_interpreter_interrupt
    janet_interpreter_interrupt(vm1);
    janet_interpreter_interrupt(NULL); // Test with NULL to use global VM

    // Test janet_vm_save
    janet_vm_save(vm2);

    // Cleanup
    janet_vm_free(vm1);
    janet_vm_free(vm2);

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

        LLVMFuzzerTestOneInput_605(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    