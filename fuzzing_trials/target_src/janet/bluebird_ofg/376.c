#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

// Function-under-test
int janet_dostring(JanetTable *env, const char *str, const char *source, Janet *out);

int LLVMFuzzerTestOneInput_376(const uint8_t *data, size_t size) {
    // Initialize Janet environment
    janet_init();

    // Create a JanetTable for the environment
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of janet_table
    JanetTable *env = janet_table(JANET_SANDBOX_THREADS);
    // End mutation: Producer.REPLACE_ARG_MUTATOR

    // Ensure the input data is null-terminated for the string parameters
    char *str = (char *)malloc(size + 1);
    if (str == NULL) {
        return 0;
    }
    memcpy(str, data, size);
    str[size] = '\0';

    // Use a static source name for simplicity
    const char *source = "fuzz_source";

    // Prepare a Janet variable to capture the output
    Janet out;

    // Call the function-under-test
    janet_dostring(env, str, source, &out);

    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_dostring to janet_channel_take
    JanetChannel* ret_janet_channel_make_threaded_flase = janet_channel_make_threaded(JANET_SANDBOX_CHROOT);
    if (ret_janet_channel_make_threaded_flase == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_channel_make_threaded_flase) {
    	return 0;
    }
    int ret_janet_channel_take_kuyuz = janet_channel_take(ret_janet_channel_make_threaded_flase, &out);
    if (ret_janet_channel_take_kuyuz < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    free(str);
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

    LLVMFuzzerTestOneInput_376(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
