#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void setup_dummy_file(const uint8_t *data, size_t size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(data, 1, size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_245(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int32_t)) return 0;

    // Initialize the Janet environment
    janet_init();

    // Allocate and initialize a JanetFuncDef
    JanetFuncDef *def = janet_funcdef_alloc();
    if (!def) {
        janet_deinit();
        return 0;
    }

    // Ensure bytecode_length is non-zero and allocate bytecode
    def->bytecode_length = Size / sizeof(uint32_t);
    if (def->bytecode_length > 0) {
        def->bytecode = (uint32_t *)janet_malloc(def->bytecode_length * sizeof(uint32_t));
        if (!def->bytecode) {
            janet_deinit();
            return 0;
        }
        memcpy(def->bytecode, Data, def->bytecode_length * sizeof(uint32_t));

        // Invoke janet_verify
        int verify_result = janet_verify(def);

        // Set a breakpoint using janet_debug_break
        int32_t pc = *((int32_t *)Data) % def->bytecode_length;
        if (pc >= 0 && pc < def->bytecode_length) {
            janet_debug_break(def, pc);

            // Remove a breakpoint using janet_debug_unbreak
            janet_debug_unbreak(def, pc);
        }

        // Disassemble the function definition
        Janet disasm_result = janet_disasm(def);

        // Create a thunk function
        JanetFunction *thunk = janet_thunk(def);

        // Handle the disasm_result and thunk if necessary
        // (In a real use case, you would do something with these results)

        // Free the allocated bytecode
        janet_free(def->bytecode);
        def->bytecode = NULL;
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

    LLVMFuzzerTestOneInput_245(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
