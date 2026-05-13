#include <stdint.h>
#include <stddef.h>
#include <janet.h>
#include "/src/janet/src/include/janet.h"

int LLVMFuzzerTestOneInput_200(const uint8_t *data, size_t size) {
    JanetTable *env;
    Janet result;

    // Initialize the Janet environment
    janet_init();

    // Create a new environment
    env = janet_core_env(NULL);

    // Ensure the data is null-terminated before passing it to janet_dostring
    char *null_terminated_data = (char *)malloc(size + 1);
    if (!null_terminated_data) {
        janet_deinit();
        return 0;
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Use janet_dostring to evaluate the input data as a Janet script
    janet_dostring(env, null_terminated_data, "fuzz", &result);

    // Free the allocated memory
    free(null_terminated_data);

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

    LLVMFuzzerTestOneInput_200(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
