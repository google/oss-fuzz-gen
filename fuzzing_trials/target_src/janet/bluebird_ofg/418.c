#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "janet.h" // Ensure the correct Janet library is included

extern JanetTable *janet_core_env(JanetTable *);

int LLVMFuzzerTestOneInput_418(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    JanetTable *inputTable = janet_table(10); // Create a new JanetTable with an initial capacity
    JanetTable *resultTable;

    if (size > 0) {
        // Use the data to fill the table with some dummy values
        for (size_t i = 0; i < size; i++) {
            Janet key = janet_wrap_integer(i);
            Janet value = janet_wrap_integer(data[i]);
            janet_table_put(inputTable, key, value);
        }
    }

    // Call the function-under-test
    resultTable = janet_core_env(inputTable);

    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_core_env to janet_table_merge_table
    JanetTable gbddxtyh;
    memset(&gbddxtyh, 0, sizeof(gbddxtyh));
    JanetTable* ret_janet_core_lookup_table_ngozq = janet_core_lookup_table(&gbddxtyh);
    if (ret_janet_core_lookup_table_ngozq == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_core_lookup_table_ngozq) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!resultTable) {
    	return 0;
    }
    janet_table_merge_table(ret_janet_core_lookup_table_ngozq, resultTable);
    // End mutation: Producer.APPEND_MUTATOR
    
    janet_gcunroot(janet_wrap_table(inputTable));

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

    LLVMFuzzerTestOneInput_418(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
