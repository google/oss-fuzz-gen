// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_local_vm at janet.c:31200:10 in janet.h
// janet_interpreter_interrupt at janet.c:31227:6 in janet.h
// janet_interpreter_interrupt_handled at janet.c:31232:6 in janet.h
// janet_vm_load at janet.c:31220:6 in janet.h
// janet_vm_save at janet.c:31216:6 in janet.h
// janet_local_vm at janet.c:31200:10 in janet.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_626(const uint8_t *Data, size_t Size) {
    // Use janet_local_vm to get a reference to a valid VM.
    JanetVM *vm1 = janet_local_vm();
    JanetVM *vm2 = janet_local_vm();

    // Fuzz janet_interpreter_interrupt and janet_interpreter_interrupt_handled
    janet_interpreter_interrupt(vm1);
    janet_interpreter_interrupt_handled(vm1);

    // Fuzz janet_vm_load and janet_vm_save
    janet_vm_load(vm1);
    janet_vm_save(vm2);

    // Do not free the VMs obtained from janet_local_vm, as they are managed internally

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

        LLVMFuzzerTestOneInput_626(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    