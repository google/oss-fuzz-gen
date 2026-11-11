#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Remove 'extern "C"' for C compatibility
int LLVMFuzzerTestOneInput_369(const uint8_t *data, size_t size) {
    // Ensure that the input data is large enough to extract necessary parameters
    if (size < sizeof(JanetFunction) + sizeof(int32_t) * 2 + sizeof(Janet)) {
        return 0;
    }

    // Initialize Janet environment
    janet_init();

    // Extract JanetFunction pointer from data
    const uint8_t *function_data = data;
    JanetFunction *func = (JanetFunction *)function_data;

    // Extract int32_t parameters from data
    const uint8_t *param1_data = data + sizeof(JanetFunction);
    int32_t param1 = *(int32_t *)param1_data;

    const uint8_t *param2_data = data + sizeof(JanetFunction) + sizeof(int32_t);
    int32_t param2 = *(int32_t *)param2_data;

    // Extract Janet pointer from data
    const uint8_t *janet_param_data = data + sizeof(JanetFunction) + sizeof(int32_t) * 2;
    Janet janet_param = *(const Janet *)janet_param_data;

    // Ensure the function and parameters are valid before calling
    if (janet_checktype(janet_wrap_function(func), JANET_FUNCTION) && janet_checktype(janet_param, JANET_NIL)) {
        // Prepare arguments for the function
        const Janet argv[2] = { janet_wrap_integer(param1), janet_wrap_integer(param2) };

        // Call the function-under-test
        JanetFiber *fiber = janet_fiber(func, 64, 2, argv);

        // Check if fiber is not null and handle the execution
        if (fiber != NULL) {
            // Execute the fiber to completion
            JanetSignal signal;
            Janet out;
            signal = janet_continue(fiber, janet_wrap_nil(), &out);

            // Handle different signals if necessary
            if (signal == JANET_SIGNAL_ERROR) {
                // Handle error signal if needed
            }
        }
    }

    // Clean up Janet environment
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

    LLVMFuzzerTestOneInput_369(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
