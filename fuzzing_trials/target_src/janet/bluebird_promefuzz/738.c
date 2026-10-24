#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "janet.h"

static void initialize_janet_env(JanetTable *env) {
    // Properly initialize a Janet environment
    janet_init();
    janet_table_init(env, 0);
}

int LLVMFuzzerTestOneInput_738(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    } // Ensure there is at least some data

    // Initialize the Janet environment
    JanetTable env;
    initialize_janet_env(&env);

    // Prepare a dummy output variable
    Janet out;

    // Prepare a source path
    const char *sourcePath = "./dummy_file";

    // Fuzz janet_dobytes
    janet_dobytes(&env, Data, (int32_t)Size, sourcePath, &out);

    // Fuzz janet_dostring if data is null-terminated
    if (Data[Size - 1] == '\0') {
        janet_dostring(&env, (const char *)Data, sourcePath, &out);
    }

    // Fuzz janet_def_sm
    if (Size > sizeof(Janet)) {
        Janet val;
        memcpy(&val, Data, sizeof(Janet));
        janet_def_sm(&env, "fuzz_symbol", val, "Fuzz documentation", sourcePath, 1);
    }

    // Fuzz janet_def
    if (Size > sizeof(Janet)) {
        Janet val;
        memcpy(&val, Data, sizeof(Janet));
        janet_def(&env, "fuzz_var", val, "Fuzz documentation");
    }

    // Fuzz janet_var
    if (Size > sizeof(Janet)) {
        Janet val;
        memcpy(&val, Data, sizeof(Janet));
        janet_var(&env, "fuzz_var", val, "Fuzz documentation");
    
        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from janet_var to janet_env_lookup_into
        JanetTable* ret_janet_table_yqqgx = janet_table(JANET_FILE_SERIALIZABLE);
        if (ret_janet_table_yqqgx == NULL){
        	return 0;
        }
        void* ret_janet_malloc_swarq = janet_malloc(JANET_SANDBOX_ASM);
        if (ret_janet_malloc_swarq == NULL){
        	return 0;
        }
        size_t ret_janet_os_rwlock_size_ojoqm = janet_os_rwlock_size();
        if (ret_janet_os_rwlock_size_ojoqm < 0){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_janet_table_yqqgx) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_janet_malloc_swarq) {
        	return 0;
        }
        janet_env_lookup_into(ret_janet_table_yqqgx, &env, (const char *)ret_janet_malloc_swarq, (int )ret_janet_os_rwlock_size_ojoqm);
        // End mutation: Producer.APPEND_MUTATOR
        
}

    // Fuzz janet_var_sm
    if (Size > sizeof(Janet)) {
        Janet val;
        memcpy(&val, Data, sizeof(Janet));
        janet_var_sm(&env, "fuzz_var_sm", val, "Fuzz documentation", sourcePath, 1);
    }

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

    LLVMFuzzerTestOneInput_738(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
