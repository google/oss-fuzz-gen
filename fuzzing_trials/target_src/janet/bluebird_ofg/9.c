#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "janet.h"

// Ensure Janet runtime is initialized before using any Janet functions
void initialize_janet_runtime_9() {
    // Initialize Janet runtime if not already initialized
    janet_init();
}

extern int janet_dobytes(JanetTable *, const uint8_t *, int32_t, const char *, Janet *);

int LLVMFuzzerTestOneInput_9(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    initialize_janet_runtime_9();

    JanetTable *env = janet_table(0);
    const char *source_name = "fuzz_input";
    Janet result;

    // Ensure the size does not exceed int32_t limits
    if (size > INT32_MAX) {
        return 0;
    }

    // Call the function-under-test
    int status = janet_dobytes(env, data, (int32_t)size, source_name, &result);

    // Check the status of the function call
    if (status != 0) {
        // Handle error if necessary
        return 0;
    }

    // Clean up Janet environment if needed

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_dobytes to janet_struct_get
    JanetKV* ret_janet_struct_begin_hlsyo = janet_struct_begin(JANET_FRAME_SIZE);
    if (ret_janet_struct_begin_hlsyo == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_struct_begin_hlsyo) {
    	return 0;
    }
    Janet ret_janet_struct_get_vpryr = janet_struct_get(ret_janet_struct_begin_hlsyo, result);
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_9(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
