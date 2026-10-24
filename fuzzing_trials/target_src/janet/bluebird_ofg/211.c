#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_211(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Create a JanetTable
    JanetTable *table = janet_table(0);

    // Use the input data to create a Janet string

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_table to janet_env_lookup_into
    // Ensure dataflow is valid (i.e., non-null)
    if (!table) {
    	return 0;
    }
    JanetTable* ret_janet_core_lookup_table_lwnks = janet_core_lookup_table(table);
    if (ret_janet_core_lookup_table_lwnks == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!table) {
    	return 0;
    }
    int32_t ret_janet_abstract_decref_focyh = janet_abstract_decref((void *)table);
    if (ret_janet_abstract_decref_focyh < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!table) {
    	return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_abstract_decref to janet_pretty
    JanetBuffer* ret_janet_buffer_zggaz = janet_buffer(-1);
    if (ret_janet_buffer_zggaz == NULL){
    	return 0;
    }
    JanetAtomicInt ret_janet_atomic_inc_khite = janet_atomic_inc(&ret_janet_abstract_decref_focyh);
    if (ret_janet_atomic_inc_khite < 0){
    	return 0;
    }
    JanetBuffer ecgnhjyp;
    memset(&ecgnhjyp, 0, sizeof(ecgnhjyp));
    Janet ret_janet_wrap_buffer_idhrt = janet_wrap_buffer(&ecgnhjyp);
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_buffer_zggaz) {
    	return 0;
    }
    JanetBuffer* ret_janet_pretty_vxnyv = janet_pretty(ret_janet_buffer_zggaz, (int )ret_janet_abstract_decref_focyh, (int )ret_janet_atomic_inc_khite, ret_janet_wrap_buffer_idhrt);
    if (ret_janet_pretty_vxnyv == NULL){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    int32_t ret_janet_abstract_decref_pcmlq = janet_abstract_decref((void *)table);
    if (ret_janet_abstract_decref_pcmlq < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_janet_core_lookup_table_lwnks) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!table) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!table) {
    	return 0;
    }
    janet_env_lookup_into(ret_janet_core_lookup_table_lwnks, table, table, (int )ret_janet_abstract_decref_pcmlq);
    // End mutation: Producer.APPEND_MUTATOR
    
    Janet key = janet_wrap_string(janet_string(data, size));

    // Insert the Janet string into the table with a dummy value
    janet_table_put(table, key, janet_wrap_nil());

    // Call the function-under-test
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

    LLVMFuzzerTestOneInput_211(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
