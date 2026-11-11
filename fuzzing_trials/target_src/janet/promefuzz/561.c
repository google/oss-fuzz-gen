// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_vm_load at janet.c:31220:6 in janet.h
// janet_vm_save at janet.c:31216:6 in janet.h
// janet_interpreter_interrupt at janet.c:31227:6 in janet.h
// janet_interpreter_interrupt at janet.c:31227:6 in janet.h
// janet_local_vm at janet.c:31200:10 in janet.h
// janet_vm_load at janet.c:31220:6 in janet.h
// janet_vm_free at janet.c:31212:6 in janet.h
// janet_vm_free at janet.c:31212:6 in janet.h
// janet_vm_alloc at janet.c:31204:10 in janet.h
// janet_vm_alloc at janet.c:31204:10 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_561(const uint8_t *Data, size_t Size) {
    // Allocate a new Janet VM
    JanetVM *vm1 = janet_vm_alloc();
    JanetVM *vm2 = janet_vm_alloc();

    // Check if allocation was successful
    if (!vm1 || !vm2) {
        return 0;
    }

    // Use the data as a dummy input for janet_vm_load
    if (Size > 0) {
        janet_vm_load(vm1);
    }

    // Save the state of vm1 into vm2
    janet_vm_save(vm2);

    // Interrupt the VM
    janet_interpreter_interrupt(vm1);
    janet_interpreter_interrupt(NULL); // Test with NULL to use global VM

    // Access the local VM
    JanetVM *local_vm = janet_local_vm();

    // Load the state from vm2 into the local VM
    janet_vm_load(vm2);

    // Free allocated VMs
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

        LLVMFuzzerTestOneInput_561(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    