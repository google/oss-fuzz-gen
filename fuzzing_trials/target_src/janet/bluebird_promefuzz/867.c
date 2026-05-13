#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static void fuzz_janet_interpreter_interrupt_handled(JanetVM *vm) {
    janet_interpreter_interrupt_handled(vm);
}

static JanetVM *fuzz_janet_local_vm(void) {
    return janet_local_vm();
}

static void fuzz_janet_vm_load(JanetVM *from) {
    janet_vm_load(from);
}

static void fuzz_janet_interpreter_interrupt(JanetVM *vm) {
    janet_interpreter_interrupt(vm);
}

static void fuzz_janet_vm_save(JanetVM *into) {
    janet_vm_save(into);
}

static void fuzz_janet_vm_free(JanetVM *vm) {
    if (vm) {
        janet_vm_free(vm);
    }
}

int LLVMFuzzerTestOneInput_867(const uint8_t *Data, size_t Size) {
    // Ensure there is enough data to create two pointers
    if (Size < 2 * sizeof(void *)) {
        return 0;
    }

    // Allocate memory for JanetVM structures using janet_local_vm
    JanetVM *vm1 = janet_local_vm();
    JanetVM *vm2 = janet_local_vm();

    // Fuzz janet_interpreter_interrupt_handled
    fuzz_janet_interpreter_interrupt_handled(NULL);
    fuzz_janet_interpreter_interrupt_handled(vm1);

    // Fuzz janet_local_vm
    JanetVM *local_vm = fuzz_janet_local_vm();

    // Fuzz janet_vm_load
    fuzz_janet_vm_load(vm1);
    fuzz_janet_vm_load(vm2);

    // Fuzz janet_interpreter_interrupt
    fuzz_janet_interpreter_interrupt(NULL);
    fuzz_janet_interpreter_interrupt(vm1);

    // Fuzz janet_vm_save
    fuzz_janet_vm_save(vm1);
    fuzz_janet_vm_save(vm2);

    // Note: janet_vm_free should not be called on VMs obtained from janet_local_vm

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

    LLVMFuzzerTestOneInput_867(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
