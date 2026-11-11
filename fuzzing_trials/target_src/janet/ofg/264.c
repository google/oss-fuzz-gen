#include <stdint.h>
#include <stdlib.h>
#include "/src/janet/src/include/janet.h" // Ensure the correct path for JanetVM functions

int LLVMFuzzerTestOneInput_264(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    if (size > 0) {
        // Convert the input data to a string and ensure it's null-terminated
        char *input = (char *)malloc(size + 1);
        if (input == NULL) {
            janet_deinit();
            return 0;
        }
        memcpy(input, data, size);
        input[size] = '\0';

        // Use janet_dostring to process the input as a Janet script
        JanetTable *env = janet_core_env(NULL);
        Janet result;
        janet_dostring(env, input, "fuzz_input", &result);

        free(input);
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

    LLVMFuzzerTestOneInput_264(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
