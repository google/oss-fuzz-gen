#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"
#include <string.h>

// Ensure that the Janet library is initialized before calling janet_local_vm
void initialize_janet_72() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

int LLVMFuzzerTestOneInput_72(const uint8_t *data, size_t size) {
    // Initialize the Janet library
    initialize_janet_72();

    // Check if the input size is zero and return early to avoid issues
    if (size == 0) {
        return 0;
    }

    // Convert the input data to a Janet string
    JanetString janet_input = janet_string(data, size);

    // Create a new Janet environment and execute the string
    JanetTable *env = janet_core_env(NULL);
    Janet result;
    Janet out;
    Janet eval_sym = janet_csymbolv("eval"); // Use janet_csymbolv instead of janet_ckeywordv
    JanetBindingType binding_type = janet_resolve(env, janet_unwrap_symbol(eval_sym), &out);

    // Check if the binding is valid and of function type
    if (binding_type != JANET_BINDING_DEF || !janet_checktype(out, JANET_FUNCTION)) {
        return 0; // If the function is not found, return early
    }

    JanetFunction *func = janet_unwrap_function(out);

    const Janet argv[1] = {janet_wrap_string(janet_input)};
    JanetFiber *fiber = janet_fiber(func, 64, 1, argv);

    // Check if the fiber was created successfully
    if (fiber == NULL) {
        return 0;
    }

    // Execute the fiber and ignore any errors for fuzzing purposes
    janet_continue(fiber, janet_wrap_nil(), &result);

    // Return 0 to indicate successful execution
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

    LLVMFuzzerTestOneInput_72(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
