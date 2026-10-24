#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Include the correct header file for janet_loop
#include "janet.h"

// Remove the janet_initialize function declaration since it's causing an undefined reference error
// The janet_initialize function does not exist in the Janet library, so we should not declare it

int LLVMFuzzerTestOneInput_399(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Create a new Janet environment
    JanetTable *env = janet_core_env(NULL);

    // Call the function-under-test

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_core_env to janet_table_merge_table
    JanetTable* ret_janet_table_weakk_yndfo = janet_table_weakk(JANET_SANDBOX_FS_READ);
    if (ret_janet_table_weakk_yndfo == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_table_weakk_yndfo) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!env) {
    	return 0;
    }
    janet_table_merge_table(ret_janet_table_weakk_yndfo, env);
    // End mutation: Producer.APPEND_MUTATOR
    
    janet_loop();

    // Clean up the Janet environment
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

    LLVMFuzzerTestOneInput_399(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
