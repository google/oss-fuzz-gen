#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_538(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Create a JanetTable
    JanetTable *table = janet_table(0);

    // Use the input data to create a Janet string
    Janet key = janet_wrap_string(janet_string(data, size));

    // Insert the Janet string into the table with a dummy value
    janet_table_put(table, key, janet_wrap_nil());

    // Call the function-under-test

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_table_put to janet_table_merge_table
    JanetTable* ret_janet_table_exizd = janet_table(JANET_STACKFRAME_ENTRANCE);
    if (ret_janet_table_exizd == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_table_exizd) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!table) {
    	return 0;
    }
    janet_table_merge_table(ret_janet_table_exizd, table);
    // End mutation: Producer.APPEND_MUTATOR
    
    JanetTable *result = janet_core_env(table);

    // Cleanup Janet environment
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

    LLVMFuzzerTestOneInput_538(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
