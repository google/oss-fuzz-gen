#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

static void initialize_janet_table(JanetTable *table) {
    memset(table, 0, sizeof(JanetTable));
    table->capacity = 8; // Arbitrary initial capacity
    table->data = (JanetKV *)calloc(table->capacity, sizeof(JanetKV));
}

int LLVMFuzzerTestOneInput_351(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    } // Ensure there is at least some data

    // Initialize the Janet environment
    janet_init();
    JanetTable env;
    initialize_janet_table(&env);

    // Prepare a dummy output
    Janet out;
    out.u64 = 0; // Initialize Janet union to avoid undefined behavior

    // Fuzz janet_dobytes
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of janet_dobytes
    janet_dobytes(&env, Data, JANET_FILE_CLOSED, "./dummy_file", &out);
    // End mutation: Producer.REPLACE_ARG_MUTATOR

    // Fuzz janet_dostring
    char *nullTerminatedString = (char *)malloc(Size + 1);
    if (nullTerminatedString) {
        memcpy(nullTerminatedString, Data, Size);
        nullTerminatedString[Size] = '\0'; // Ensure null termination
        janet_dostring(&env, nullTerminatedString, "./dummy_file", &out);

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_dostring to janet_marshal
        JanetBuffer* ret_janet_buffer_ileto = janet_buffer(JANET_LITTLE_ENDIAN);
        if (ret_janet_buffer_ileto == NULL){
        	return 0;
        }
        JanetTable* ret_janet_table_weakk_xxchc = janet_table_weakk(JANET_EV_TCTAG_ERR_KEYWORD);
        if (ret_janet_table_weakk_xxchc == NULL){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_janet_buffer_ileto) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_janet_table_weakk_xxchc) {
        	return 0;
        }
        janet_marshal(ret_janet_buffer_ileto, out, ret_janet_table_weakk_xxchc, JANET_EV_TCTAG_NIL);
        // End mutation: Producer.APPEND_MUTATOR
        
        free(nullTerminatedString);
    }

    // Fuzz janet_def_sm
    janet_def_sm(&env, "dummySymbol", out, "dummy documentation", "./dummy_file", 1);

    // Fuzz janet_def
    janet_def(&env, "dummyVar", out, "dummy documentation");

    // Fuzz janet_env_lookup_into
    JanetTable renv;
    initialize_janet_table(&renv);
    janet_env_lookup_into(&renv, &env, "prefix_", 1);

    // Fuzz janet_var_sm
    janet_var_sm(&env, "dummyVarSM", out, "dummy documentation", "./dummy_file", 1);

    // Clean up
    free(env.data);
    free(renv.data);
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

    LLVMFuzzerTestOneInput_351(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
