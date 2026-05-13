// This fuzz driver is generated for library janet, aiming to fuzz the following functions:
// janet_vm_alloc at janet.c:31204:10 in janet.h
// janet_vm_free at janet.c:31212:6 in janet.h
// janet_local_vm at janet.c:31200:10 in janet.h
// janet_interpreter_interrupt at janet.c:31227:6 in janet.h
// janet_vm_alloc at janet.c:31204:10 in janet.h
// janet_vm_alloc at janet.c:31204:10 in janet.h
// janet_vm_load at janet.c:31220:6 in janet.h
// janet_vm_load at janet.c:31220:6 in janet.h
// janet_vm_free at janet.c:31212:6 in janet.h
// janet_vm_free at janet.c:31212:6 in janet.h
// janet_vm_alloc at janet.c:31204:10 in janet.h
// janet_interpreter_interrupt at janet.c:31227:6 in janet.h
// janet_vm_free at janet.c:31212:6 in janet.h
// janet_vm_alloc at janet.c:31204:10 in janet.h
// janet_vm_alloc at janet.c:31204:10 in janet.h
// janet_vm_save at janet.c:31216:6 in janet.h
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

static void fuzz_janet_vm_alloc() {
    JanetVM *vm = janet_vm_alloc();
    if (vm) {
        janet_vm_free(vm);
    }
}

static void fuzz_janet_local_vm() {
    JanetVM *vm = janet_local_vm();
    if (vm) {
        janet_interpreter_interrupt(vm);
    }
}

static void fuzz_janet_vm_load() {
    JanetVM *vm1 = janet_vm_alloc();
    JanetVM *vm2 = janet_vm_alloc();
    if (vm1 && vm2) {
        janet_vm_load(vm1);
        janet_vm_load(vm2);
        janet_vm_free(vm1);
        janet_vm_free(vm2);
    }
}

static void fuzz_janet_interpreter_interrupt() {
    JanetVM *vm = janet_vm_alloc();
    if (vm) {
        janet_interpreter_interrupt(vm);
        janet_vm_free(vm);
    }
}

static void fuzz_janet_vm_save() {
    JanetVM *vm1 = janet_vm_alloc();
    JanetVM *vm2 = janet_vm_alloc();
    if (vm1 && vm2) {
        janet_vm_save(vm1);
        janet_vm_save(vm2);
        janet_vm_free(vm1);
        janet_vm_free(vm2);
    }
}

int LLVMFuzzerTestOneInput_229(const uint8_t *Data, size_t Size) {
    fuzz_janet_vm_alloc();
    fuzz_janet_local_vm();
    fuzz_janet_vm_load();
    fuzz_janet_interpreter_interrupt();
    fuzz_janet_vm_save();
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

        LLVMFuzzerTestOneInput_229(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    