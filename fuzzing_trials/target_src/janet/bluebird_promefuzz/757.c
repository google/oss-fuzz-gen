#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

// Initialize Janet VM before fuzzing
static void initialize_janet_vm() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

static JanetEVGenericMessage dummy_subroutine(JanetEVGenericMessage msg) {
    // Dummy subroutine for janet_ev_threaded_await
    return msg;
}

int LLVMFuzzerTestOneInput_757(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(JanetFunction) + sizeof(Janet)) return 0;

    // Initialize Janet VM
    initialize_janet_vm();

    // Prepare a dummy JanetFunction and Janet array for arguments
    JanetFunction callee;
    memset(&callee, 0, sizeof(JanetFunction)); // Ensure callee is properly initialized
    Janet argv[1];
    argv[0].u64 = *(const uint64_t *)Data;

    // Ensure a valid JanetFuncDef for the callee
    JanetFuncDef funcdef;
    memset(&funcdef, 0, sizeof(JanetFuncDef)); // Properly initialize funcdef
    callee.def = &funcdef; // Set the function definition for the callee

    // Initialize a JanetFiber
    JanetFiber *fiber = janet_fiber(&callee, 10, 1, argv);
    if (!fiber) return 0;

    // Fuzz janet_loop_fiber
    janet_loop_fiber(fiber);

    // Fuzz janet_getfiber
    JanetFiber *retrieved_fiber = janet_getfiber(argv, 0);

    // Fuzz janet_pcall
    Janet out;
    JanetSignal signal = janet_pcall(&callee, 1, argv, &out, &retrieved_fiber);

    // Fuzz janet_ev_threaded_await
    janet_ev_threaded_await(dummy_subroutine, 0, 0, NULL);

    // Clean up
    janet_free(fiber);

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

    LLVMFuzzerTestOneInput_757(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
