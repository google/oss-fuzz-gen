#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

// Function-under-test
int janet_dostring(JanetTable *env, const char *str, const char *source, Janet *out);

int LLVMFuzzerTestOneInput_146(const uint8_t *data, size_t size) {
    // Initialize Janet environment
    janet_init();

    // Create a JanetTable for the environment
    JanetTable *env = janet_table(0);

    // Ensure the input data is null-terminated for the string parameters

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_table to janet_compile
    JanetFuncDef voxeshav;
    memset(&voxeshav, 0, sizeof(voxeshav));
    Janet ret_janet_disasm_nsfsj = janet_disasm(&voxeshav);
    size_t ret_janet_os_mutex_size_nomvb = janet_os_mutex_size();
    if (ret_janet_os_mutex_size_nomvb < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!env) {
    	return 0;
    }

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from janet_os_mutex_size to janet_array using the plateau pool
    JanetArray* ret_janet_array_rylbb = janet_array((int32_t )ret_janet_os_mutex_size_nomvb);
    if (ret_janet_array_rylbb == NULL){
    	return 0;
    }
    // End mutation: Producer.SPLICE_MUTATOR
    
    JanetCompileResult ret_janet_compile_mxtee = janet_compile(ret_janet_disasm_nsfsj, env, (const uint8_t *)&ret_janet_os_mutex_size_nomvb);
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_146(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
