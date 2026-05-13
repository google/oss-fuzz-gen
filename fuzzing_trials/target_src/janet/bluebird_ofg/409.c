#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

// Function-under-test
int janet_dostring(JanetTable *env, const char *str, const char *source, Janet *out);

int LLVMFuzzerTestOneInput_409(const uint8_t *data, size_t size) {
    // Initialize Janet environment
    janet_init();

    // Create a JanetTable for the environment
    JanetTable *env = janet_table(0);

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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_dostring to janet_table_get_ex
    // Ensure dataflow is valid (i.e., non-null)
    if (!env) {
    	return 0;
    }
    JanetTable* ret_janet_core_env_xbjzb = janet_core_env(env);
    if (ret_janet_core_env_xbjzb == NULL){
    	return 0;
    }
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function janet_table_weakk with janet_table
    JanetTable* ret_janet_table_weakk_jahry = janet_table(JANET_SANDBOX_SIGNAL);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR
    if (ret_janet_table_weakk_jahry == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!env) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_table_weakk_jahry) {
    	return 0;
    }
    Janet ret_janet_table_get_ex_zrylz = janet_table_get_ex(env, out, &ret_janet_table_weakk_jahry);
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

    LLVMFuzzerTestOneInput_409(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
